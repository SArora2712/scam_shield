import argparse, asyncio, csv
from backend import config
from backend.main import parse_script, matcher, SCRIPTS
from backend.escalation import Scorer
from backend.tts_gnani import synthesize_cached
from backend.audio_utils import wav_to_pcm
from backend.noise import degrade, LEVELS
from backend.stt_gnani import transcribe_turn
from backend.wer import wer

LANG = "en-IN"
clean_ref = {}


async def hyp_for(text, level):
    pcm16 = wav_to_pcm(synthesize_cached(text), 16000)
    pcm, rate = degrade(pcm16, level)
    return await transcribe_turn(pcm, rate, LANG, cache_key=f"{text}|{level}")


async def run_script(name, level):
    scorer, peak, wers, errors, sources = Scorer(), 0, [], 0, set()
    turns = parse_script((SCRIPTS / f"{name}.txt").read_text(encoding="utf-8"))
    for who, text in turns:
        if who != "caller":
            continue
        res = await hyp_for(text, level)
        if res["error"]:
            errors += 1
            print("   !", level, text[:40], "->", res["error"])
            continue
        sources.add(res["source"])
        if text not in clean_ref:
            ref = res if level == "clean" else await hyp_for(text, "clean")
            clean_ref[text] = None if ref["error"] else " ".join(ref["segments"])
        if level != "clean" and clean_ref[text]:
            wers.append(wer(clean_ref[text], " ".join(res["segments"])))
        for seg in res["segments"]:
            peak = max(peak, scorer.update(matcher.match(seg))["score"])
    return {"script": name, "level": level, "peak": peak, "errors": errors,
            "wer": (sum(wers) / len(wers)) if wers else None, "source": "/".join(sorted(sources))}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", default=",".join(LEVELS))
    ap.add_argument("--scripts", default=",".join(p.stem for p in sorted(SCRIPTS.glob("*.txt"))))
    a = ap.parse_args()
    levels = [l for l in LEVELS if l in a.levels.split(",")]
    scripts = a.scripts.split(",")
    rows = []
    for level in levels:
        for s in scripts:
            r = await run_script(s, level)
            rows.append(r)
            w = f"{r['wer']:.0%}" if r["wer"] is not None else "-"
            flag = "ALERT" if r["peak"] >= config.ALERT_THRESHOLD else "ok"
            print(f"{level:13} {s:11} peak={r['peak']:3} {flag:5} WER-vs-clean={w:>4} errors={r['errors']} ({r['source']})")

    print(f"\nSummary (alert threshold {config.ALERT_THRESHOLD:.0f})")
    for level in levels:
        sc = [r for r in rows if r["level"] == level and r["script"].startswith("scam")]
        nm = [r for r in rows if r["level"] == level and r["script"].startswith("normal")]
        det = f"{sum(r['peak'] >= config.ALERT_THRESHOLD for r in sc)}/{len(sc)}" if sc else "-"
        fa = f"{sum(r['peak'] >= config.ALERT_THRESHOLD for r in nm)}/{len(nm)}" if nm else "-"
        ws = [r["wer"] for r in rows if r["level"] == level and r["wer"] is not None]
        mw = f"{sum(ws) / len(ws):.0%}" if ws else "-"
        print(f"  {level:13} scams alerted {det:>4}   normal false alarms {fa:>4}   mean WER vs clean {mw}")

    if rows:
        with open("eval/noise_results.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)


if __name__ == "__main__":
    asyncio.run(main())