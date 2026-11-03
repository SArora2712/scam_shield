import argparse, csv, glob, os
from backend.main import Analysis, parse_script, combine_verdict
from backend.llm_context import classify_call
from backend.llm_context import analyse_window
from backend.llm_retry import classify_call

def summary(rows, key, title):
    print(title)
    for kind in ("scam", "normal", "spam"):
        r = [x for x in rows if x["expected"] == kind]
        if not r:
            continue
        if kind == "scam":
            print(f"  scam   n={len(r):2}  called 'Likely scam': {sum(x[key] == 'scam' for x in r)}/{len(r)}"
                  f"   flagged (scam or suspicious): {sum(x[key] in ('scam', 'suspicious') for x in r)}/{len(r)}")
        elif kind == "normal":
            print(f"  normal n={len(r):2}  false alarms (anything but 'Looks normal'): {sum(x[key] != 'safe' for x in r)}/{len(r)}"
                  f"   called 'Likely scam': {sum(x[key] == 'scam' for x in r)}/{len(r)}")
        else:
            print(f"  spam   n={len(r):2}  called spam: {sum(x[key] == 'spam' for x in r)}/{len(r)}"
                  f"   called scam: {sum(x[key] == 'scam' for x in r)}/{len(r)}")


def main():
    ap = argparse.ArgumentParser(description="Run every .txt in a folder. File names start with scam_, normal_ or spam_.")
    ap.add_argument("folder")
    ap.add_argument("--ai", action="store_true", help="also ask the AI analyst (needs GROQ_API_KEY)")
    a = ap.parse_args()
    rows = []
    for p in sorted(glob.glob(os.path.join(a.folder, "*.txt"))):
        name = os.path.basename(p)[:-4]
        an = Analysis()
        for who, seg in parse_script(open(p, encoding="utf-8").read()):
            an.step(seg, who)
        rv = an.verdict()
        ai, err = None, ""
        if a.ai:
            try:
                ai = classify_call(an.transcript())
                print(f"\nAI RESULT for {name}: {ai}\n")

            except Exception as e:
                import traceback
                traceback.print_exc()
                err = f" (AI error: {e})"
        fv = combine_verdict(rv, ai)
        rows.append({"file": name, "expected": name.split("_")[0], "rules_level": rv["level"], "level": fv["level"],
                     "final": fv["label"], "peak": rv["peak"], "decided_by": fv["decided_by"],
                     "ai_label": ai["label"] if ai else "", "tactics": "|".join(e["tactic"] for e in rv["evidence"])})
        print(f"{name:26} expected={rows[-1]['expected']:7} rules={rv['label']:30} final={fv['label']:34} by={fv['decided_by']}{err}")
    if not rows:
        print("No .txt files found.")
        return
    print()
    summary(rows, "rules_level", "Rules and embeddings only:")
    if a.ai:
        successful_ai_rows = [
            row for row in rows if row["ai_label"]
        ]

        failed_ai = len(rows) - len(successful_ai_rows)

        print(
            f"\nAI evaluations successful: "
            f"{len(successful_ai_rows)}/{len(rows)}"
        )
        print(f"AI evaluations failed: {failed_ai}/{len(rows)}")

        if successful_ai_rows:
            summary(
                successful_ai_rows,
                "level",
                "Rules + AI analyst (successful calls only):"
            )
    with open("eval/folder_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()