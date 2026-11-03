"""Re-reads eval/folder_results.csv and compares ways of combining the rules and the AI analyst.
No new AI calls are made."""
import csv, sys

path = sys.argv[1] if len(sys.argv) > 1 else "eval/folder_results.csv"
rows = list(csv.DictReader(open(path, encoding="utf-8")))
AI = {"scam": "scam", "spam": "spam", "normal": "safe"}


def ai_only(r):
    return AI.get(r.get("ai_label", ""))


def ai_first(r):
    ai, rules = AI.get(r.get("ai_label", "")), r["rules_level"]
    if ai is None:
        return rules                                   # AI failed: fall back to the rules
    if ai == "scam":
        return "scam"
    if rules == "scam":
        return "suspicious"                            # rules and AI disagree
    return ai                                          # "spam" or "safe"


POLICIES = [("rules only", lambda r: r["rules_level"]),
            ("current (rules + AI)", lambda r: r.get("level")),
            ("AI only", ai_only),
            ("AI first, rules as safety net", ai_first)]


def show(name, fn):
    print(name)
    for kind in ("scam", "normal", "spam"):
        sel = [(r, fn(r)) for r in rows if r["expected"] == kind]
        sel = [(r, lv) for r, lv in sel if lv]
        if not sel:
            continue
        n = len(sel)
        c = lambda *lv: sum(lv_ in lv for _, lv_ in sel)
        if kind == "scam":
            print(f"  scam   n={n:2}  called scam {c('scam')}/{n}   flagged (scam or suspicious) {c('scam', 'suspicious')}/{n}")
        elif kind == "normal":
            print(f"  normal n={n:2}  false alarms {n - c('safe')}/{n}   of which called scam {c('scam')}/{n}")
        else:
            print(f"  spam   n={n:2}  called spam {c('spam')}/{n}   called scam {c('scam')}/{n}")


for name, fn in POLICIES:
    show(name, fn)
print()
print("Normal calls the rules flagged (tactic names only):")
for r in rows:
    if r["expected"] == "normal" and r["rules_level"] != "safe":
        print(f"  {r['file']:22} rules={r['rules_level']:10} ai={r.get('ai_label') or '-':7} tactics={r['tactics']}")
print("Scam calls the AI did not call scam:")
for r in rows:
    if r["expected"] == "scam" and r.get("ai_label") not in ("scam", "", None):
        print(f"  {r['file']:22} ai={r['ai_label']}")