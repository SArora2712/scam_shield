import argparse, csv, re
from collections import Counter
from backend.embeddings import Matcher
from backend.escalation import Scorer
from backend.segmenter import split_segments
from backend import config

ROBO = re.compile(r"press (1|one|2|two|5|five|9|nine)\b", re.I)


def load_entries(path):
    raw = open(path, encoding="utf-8", errors="ignore").read()
    out = []
    for p in re.split(r"(?m)^\s*\d+\.\s+", raw):
        p = re.sub(r"^(\d+\.\s*)+", "", p.strip())
        p = re.sub(r"\s+", " ", p)
        if len(p.split()) >= 5:
            out.append(p)
    return out


def run_entry(m, text):
    s, peak, tactics = Scorer(), 0, []
    for seg in split_segments(text):
        out = s.update(m.match(seg))
        peak, tactics = max(peak, out["score"]), out["tactics"]
    return peak, tactics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scam", required=True)
    ap.add_argument("--normal", required=True)
    ap.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    ap.add_argument("--skip-robocall", action="store_true", help="skip 'press 1' robocall style entries")
    a = ap.parse_args()

    m, rows = Matcher(), []
    for label, path in (("scam", a.scam), ("normal", a.normal)):
        for i, text in enumerate(load_entries(path)):
            if a.split == "dev" and i % 2:
                continue
            if a.split == "test" and i % 2 == 0:
                continue
            if a.skip_robocall and ROBO.search(text):
                continue
            peak, tactics = run_entry(m, text)
            rows.append((label, i, peak, tactics, text))

    print(f"split={a.split}  alert threshold={config.ALERT_THRESHOLD:.0f}")
    for label in ("scam", "normal"):
        r = [x for x in rows if x[0] == label]
        if r:
            alert = sum(x[2] >= config.ALERT_THRESHOLD for x in r)
            flag = sum(x[2] >= 30 for x in r)
            what = "detection rate" if label == "scam" else "false-alarm rate"
            print(f"{label:7} n={len(r):3}  {what} (alert): {alert/len(r):.0%}   flagged(>=30): {flag/len(r):.0%}")
    tc = Counter(t for x in rows if x[0] == "scam" for t in x[3])
    print("tactics seen in scam entries:", dict(tc.most_common()))

    if a.split == "dev":   # only look at misses on the dev half
        missed = [x for x in rows if x[0] == "scam" and x[2] < config.ALERT_THRESHOLD]
        print(f"\nmissed scam entries (dev): {len(missed)}; first 8:")
        for x in missed[:8]:
            print(f"  #{x[1]} peak={x[2]} {x[3]} | {x[4][:110]}")

    with open("eval/results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "index", "peak_score", "tactics", "text"])
        for x in rows:
            w.writerow([x[0], x[1], x[2], "|".join(x[3]), x[4][:200]])


if __name__ == "__main__":
    main()