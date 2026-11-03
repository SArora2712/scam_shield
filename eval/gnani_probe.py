import argparse, asyncio
from backend.tts_gnani import synthesize_cached
from backend.stt_gnani import stream_transcripts
from backend.audio_utils import wav_to_pcm

LINES = [
    "Namaste sir, main State Bank ke fraud department se officer bol raha hoon.",
    "Aapka account block ho jayega, abhi KYC update kijiye.",
    "Yeh baat confidential hai, kisi ko mat batana.",
    "Apne phone par aaya hua code bata dijiye.",
    "AnyDesk download kar lijiye, main aapki screen dekh kar madad karunga.",
]


async def transcribe(pcm, rate, lang, tries=2):
    err = None
    for _ in range(tries):
        texts, lats = [], []
        try:
            async for ev in stream_transcripts(pcm, rate, lang):
                if ev["type"] == "transcript":
                    texts.append(ev["text"])
                    lats.append(ev.get("latency"))
                else:
                    err = ev.get("message")
        except Exception as e:
            err = str(e)
        if texts:
            return " ".join(texts), lats
        await asyncio.sleep(2)          # one retry if nothing came back
    return f"[no transcript: {err}]", []


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=int, default=16000)       # use 8000 for the telephony test
    ap.add_argument("--langs", default="en-IN")
    a = ap.parse_args()
    chars = secs = 0
    for line in LINES:
        wav = synthesize_cached(line)                          # 48 kHz from Timbre (cached)
        pcm = wav_to_pcm(wav, a.rate)
        chars += len(line)
        print("\nSAID :", line)
        for lang in a.langs.split(","):
            secs += len(pcm) / 2 / a.rate
            text, lats = await transcribe(pcm, a.rate, lang)
            print(f"{lang:6}:", text, "| latency ms:", lats)
    print(f"\nPrisma audio sent: about {secs:.0f} s (plus 2 s of silence per call; retries add more)")


if __name__ == "__main__":
    asyncio.run(main())