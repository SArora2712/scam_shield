import sys
from backend.main import parse_script, matcher, SCRIPTS
from backend.escalation import Scorer
from backend import config

verbose = "-v" in sys.argv
for p in sorted(SCRIPTS.glob("*.txt")):
    s, peak, rows = Scorer(), 0, []
    for who, text in parse_script(p.read_text(encoding="utf-8")):
        sig = matcher.match(text) if who == "caller" else []
        out = s.update(sig)
        peak = max(peak, out["score"])
        rows.append((out["score"], who, text[:70], [(t[:14], v) for t, v in sig]))
    kind = "SCAM  " if p.stem.startswith("scam") else "NORMAL"
    status = "ALERT" if peak >= config.ALERT_THRESHOLD else "ok"
    print(f"{kind} {p.stem:12} peak={peak:3} {status}")
    if verbose or (kind == "NORMAL" and peak >= 30):
        for r in rows:
            print("   ", str(r[0]).rjust(3), r[1].ljust(7), r[2], r[3])
            