import json, math, re
from collections import Counter
from .lexicon import lexical_hits
import numpy as np

from . import config

_TACTICS = json.loads((config.ROOT / "data" / "tactics.json").read_text(encoding="utf-8"))
_NORMAL = _TACTICS.pop("_normal", [])
_tok = lambda s: re.findall(r"[a-z0-9\u0900-\u097f]+", s.lower())

def _clean(s):
    """Same look as Prisma's output: lowercase, no punctuation."""
    s = s.lower().replace("\u0964", " ")
    s = re.sub(r"[^\w\s\u0900-\u097f]", " ", s)
    return re.sub(r"\s+", " ", s).strip()

MARGIN = 0.04  # keep only tactics very close to the best match


def _norm(a):
    a = np.asarray(a, dtype=np.float32)
    return a / np.maximum(np.linalg.norm(a, axis=-1, keepdims=True), 1e-9)


def _load_encoder():
    """Returns a function: list[str] -> normalised numpy array."""
    if config.EMBED_BACKEND == "fastembed":
        from fastembed import TextEmbedding
        m = TextEmbedding("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
                          cache_dir=str(config.ROOT / ".cache"))
        return lambda texts: _norm(list(m.embed(texts)))
    from sentence_transformers import SentenceTransformer
    m = SentenceTransformer(config.EMBED_MODEL)
    return lambda texts: _norm(m.encode(texts))


class Matcher:
    def __init__(self):
        self.examples = [(t, ex) for t, exs in _TACTICS.items() for ex in exs]
        self.encode = None
        if config.USE_EMBEDDINGS:
            self.encode = _load_encoder()
            self.vecs = self.encode([_clean(e) for _, e in self.examples])
            self.normal_vecs = self.encode([_clean(e) for e in _NORMAL])
        else:
            self.bows = [Counter(_tok(e)) for _, e in self.examples]
            self.normal_bows = [Counter(_tok(e)) for e in _NORMAL]

    @staticmethod
    def _cos(a, b):
        num = sum(a[k] * b.get(k, 0) for k in a)
        den = math.sqrt(sum(v * v for v in a.values())) * math.sqrt(sum(v * v for v in b.values()))
        return num / den if den else 0.0

    def match(self, text):
        """Embedding matches plus rule-based matches, merged (highest confidence per tactic)."""
        merged = {}
        for t, s in self._match_embeddings(text) + lexical_hits(text):
            merged[t] = max(merged.get(t, 0.0), s)
        return sorted(merged.items(), key=lambda x: -x[1])

    def _match_embeddings(self, text):
        """Returns [(tactic, similarity)]. Empty if the line looks like normal talk."""
        if self.encode is not None:
            q = self.encode([_clean(text)])[0]
            sims = (self.vecs @ q).tolist()
            normal_best = float((self.normal_vecs @ q).max())
        else:
            q = Counter(_tok(_clean(text)))
            sims = [self._cos(q, b) for b in self.bows]
            normal_best = max(self._cos(q, b) for b in self.normal_bows)
        best = {}
        for (tactic, _), s in zip(self.examples, sims):
            best[tactic] = max(best.get(tactic, 0.0), s)
        hits = {t: s for t, s in best.items() if s >= config.MATCH_THRESHOLD}
        if not hits:
            return []
        top = max(hits.values())
        if normal_best >= top:          # closer to normal talk than to any scam tactic
            return []
        chosen = sorted([(t, round(s, 3)) for t, s in hits.items() if s >= top - MARGIN], key=lambda x: -x[1])
        if len(chosen) >= 4:      # a line matching many unrelated tactics about equally is generic, not specific
            return []
        return chosen[:2]