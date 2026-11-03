import hashlib
import requests
from . import config

URL = "https://api.vachana.ai/api/v1/tts/inference"

WARNING_LINES = [
    "Savdhaan! Yeh call scam ho sakti hai. Apna OTP ya PIN kisi ko na batayein.",
    "Warning: this call shows signs of a scam. Do not share OTP, PIN or send money.",
]


def synthesize(text, voice="Nalini", language="hi-IN", sample_rate=48000):
    if not config.GNANI_API_KEY:
        raise RuntimeError("GNANI_API_KEY is empty. Put it in .env")
    body = {"text": text, "voice": voice, "model": "timbre-v2.5", "language": language, "speed": 1.0,
            "audio_config": {"sample_rate": sample_rate, "num_channels": 1, "sample_width": 2,
                             "encoding": "linear_pcm", "container": "wav"}}
    r = requests.post(URL, json=body, headers={"X-API-Key-ID": config.GNANI_API_KEY}, timeout=60)
    r.raise_for_status()
    return r.content


def synthesize_cached(text, voice="Nalini", language="hi-IN", sample_rate=48000):
    """Credits are limited, so every line is generated once and reused."""
    key = hashlib.md5(f"{text}|{voice}|{language}|{sample_rate}".encode()).hexdigest()[:12]
    path = config.ROOT / "data" / "audio" / f"tts_{key}.wav"
    if path.exists():
        return path.read_bytes()
    data = synthesize(text, voice, language, sample_rate)
    path.write_bytes(data)
    return data