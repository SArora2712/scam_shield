import asyncio, hashlib, json, time
import requests
import websockets
from . import config

URL = "wss://api.vachana.ai/stt/v3/stream"


def _headers(language, rate):
    h = {"x-api-key-id": config.GNANI_API_KEY, "language_code": language, "x-sample-rate": str(rate)}
    if rate == 8000:   # telephony preset from the Gnani docs
        h.update({"x-vad-threshold": "0.7", "x-min-speech-ms": "200", "x-min-silence-ms": "500"})
    return h


async def stream_transcripts(pcm, sample_rate=16000, language="en-IN", pace=1.0):
    """Send raw PCM at real-time pace. Yields server events: transcripts and (non-fatal) errors."""
    if not config.GNANI_API_KEY:
        raise RuntimeError("GNANI_API_KEY is empty. Put it in .env")
    frame_s = 512 / sample_rate                       # 32 ms @16k, 64 ms @8k
    pcm = pcm + bytes(sample_rate * 2 * 2)            # 2 s of silence so the last sentence closes
    q = asyncio.Queue()

    # note: on websockets < 13 use extra_headers instead of additional_headers
    async with websockets.connect(URL, additional_headers=_headers(language, sample_rate),
                                  max_size=None) as ws:
        async def send():
            try:
                for i in range(0, len(pcm), 1024):
                    chunk = pcm[i:i + 1024]
                    await ws.send(chunk + bytes(1024 - len(chunk)))   # every frame exactly 1024 bytes
                    await asyncio.sleep(frame_s / pace)
            except websockets.ConnectionClosed:
                pass

        async def recv():
            try:
                async for raw in ws:
                    await q.put(json.loads(raw))
            except websockets.ConnectionClosed:
                pass
            finally:
                await q.put(None)

        sender, receiver = asyncio.create_task(send()), asyncio.create_task(recv())
        got = False
        try:
            while True:
                try:
                    wait = (1.5 if got else 5) if sender.done() else 30
                    msg = await asyncio.wait_for(q.get(), timeout=wait)
                except asyncio.TimeoutError:
                    break
                if msg is None:
                    break
                if msg.get("type") in ("transcript", "error"):
                    got = got or msg.get("type") == "transcript"
                    yield msg          # the caller decides what to do with an error frame
        finally:
            sender.cancel()
            receiver.cancel()



def _cache_path():
    p = config.ROOT / "data" / "cache" / "stt.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_cache():
    p = _cache_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


async def transcribe_turn(pcm, rate, language="en-IN", cache_key=None, use_cache=True):
    """One call turn -> {"segments": [...], "latency_ms": [...], "error": str|None, "source": "live"|"cached"}.
    Successful results are cached so repeat runs cost no credits. Failures are never cached."""
    cache = _load_cache()
    k = hashlib.sha1(f"{cache_key}|{language}|{rate}".encode()).hexdigest()[:16] if cache_key else None
    if use_cache and k and k in cache:
        return {**cache[k], "source": "cached"}
    segs, lats, err = [], [], None
    for _ in range(2):                                   # one retry for one-off server errors
        segs, lats = [], []
        try:
            async for ev in stream_transcripts(pcm, rate, language):
                if ev["type"] == "transcript":
                    segs.append(ev["text"])
                    lats.append(ev.get("latency"))
                else:
                    err = ev.get("message")
        except Exception as e:
            err = str(e)
        if segs:
            break
        await asyncio.sleep(2)
    out = {"segments": segs, "latency_ms": lats, "error": None if segs else err}
    if segs and k:
        cache[k] = out
        _cache_path().write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    return {**out, "source": "live"}  



REST_URL = "https://api.vachana.ai/stt/v3"


def transcribe_clip(wav_bytes, language="en-IN"):
    """Prisma v2.5 REST call for a clip of up to 30 s. Returns the transcript text. Raises on error."""
    if not config.GNANI_API_KEY:
        raise RuntimeError("GNANI_API_KEY is empty. Put it in .env")
    r = requests.post(REST_URL, headers={"X-API-Key-ID": config.GNANI_API_KEY},
                      files={"audio_file": ("clip.wav", wav_bytes, "audio/wav")},
                      data={"language_code": language}, timeout=60)
    if r.status_code == 429:
        raise RuntimeError("Gnani allows one request at a time on this account. Wait a moment and try again.")
    try:
        body = r.json()
    except ValueError:
        raise RuntimeError(f"Prisma returned a non-JSON reply (HTTP {r.status_code})")
    if r.status_code != 200 or body.get("success") is False:
        err = body.get("error") or {}
        msg = err.get("message") if isinstance(err, dict) else None
        raise RuntimeError(f"Prisma error {r.status_code}: {msg or body.get('detail') or body}")
    return body.get("transcript", "")


def transcribe_clip_cached(wav_bytes, language="en-IN", use_cache=True):
    """-> {"text": str, "source": "live" | "cached"}. Successful results are cached by audio hash."""
    k = "clip|" + hashlib.sha1(wav_bytes).hexdigest()[:20] + "|" + language
    cache = _load_cache()
    if use_cache and k in cache:
        return {"text": cache[k]["text"], "source": "cached"}
    err = None
    for attempt in range(2):                      # one retry for network blips
        try:
            text = transcribe_clip(wav_bytes, language)
            cache[k] = {"text": text}
            _cache_path().write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
            return {"text": text, "source": "live"}
        except Exception as e:
            err = e
            time.sleep(2)
    raise err