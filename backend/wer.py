import re


def _words(s):
    return re.sub(r"[^\w\s\u0900-\u097f]", " ", s.lower()).split()


def wer(ref, hyp):
    """Word error rate (edit distance / reference length). Pure python."""
    r, h = _words(ref), _words(hyp)
    if not r:
        return 0.0 if not h else 1.0
    d = list(range(len(h) + 1))
    for i, rw in enumerate(r, 1):
        prev, d[0] = d[0], i
        for j, hw in enumerate(h, 1):
            cur = min(d[j] + 1, d[j - 1] + 1, prev + (rw != hw))
            prev, d[j] = d[j], cur
    return d[len(h)] / len(r)