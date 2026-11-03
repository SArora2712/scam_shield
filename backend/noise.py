"""F7: noise slider. Four named levels, numpy only, reproducible (fixed seed)."""
import numpy as np

# level -> output sample rate sent to Prisma
LEVELS = {"clean": 16000, "market": 16000, "phone": 8000, "phone_market": 8000,
          "market_hard": 16000, "phone_hard": 8000}
MARKET_SNR_DB = {"market": 8, "phone_market": 8, "market_hard": 0, "phone_hard": 0}  # lower = harsher   # speech vs market noise (lower = harsher)
LINE_SNR_DB = 25       # light hiss on the phone line


def _pink(n, rng):
    spec = np.fft.rfft(rng.standard_normal(n))
    f = np.arange(len(spec), dtype=np.float32)
    f[0] = 1
    x = np.fft.irfft(spec / np.sqrt(f), n)
    return x / (np.std(x) + 1e-9)


def _babble(x, rng, voices=5):
    """Crowd murmur: reversed, time-shifted copies of the speech itself."""
    out = np.zeros_like(x)
    for _ in range(voices):
        out += np.roll(x[::-1], int(rng.integers(1, max(2, len(x)))))
    return out / (np.std(out) + 1e-9)


def _mix(x, noise, snr_db):
    g = np.sqrt((np.mean(x ** 2) + 1e-9) / ((np.mean(noise ** 2) + 1e-9) * 10 ** (snr_db / 10)))
    return x + g * noise


def _bandlimit(x, rate, lo=300, hi=3400):
    spec = np.fft.rfft(x)
    freqs = np.fft.rfftfreq(len(x), 1 / rate)
    spec[(freqs < lo) | (freqs > hi)] = 0
    return np.fft.irfft(spec, len(x))


def _mulaw(x, mu=255):
    """8-bit mu-law, like a phone codec."""
    y = np.sign(x) * np.log1p(mu * np.abs(x)) / np.log1p(mu)
    y = np.round((y + 1) / 2 * 255) / 255 * 2 - 1
    return np.sign(y) * ((1 + mu) ** np.abs(y) - 1) / mu


def degrade(pcm16k, level="clean", seed=7):
    """16 kHz 16-bit mono PCM bytes -> (pcm bytes, sample_rate) at the chosen level."""
    if level not in LEVELS:
        raise ValueError(f"level must be one of {list(LEVELS)}")
    if level == "clean":
        return pcm16k, LEVELS["clean"]                  # untouched
    x = np.frombuffer(pcm16k, dtype="<i2").astype(np.float32) / 32768
    rng = np.random.default_rng(seed)
    if level in MARKET_SNR_DB:
        x = _mix(x, 0.6 * _pink(len(x), rng) + 0.4 * _babble(x, rng), MARKET_SNR_DB[level])
    if level.startswith("phone"):
        x = _bandlimit(x, 16000)
        x = x[: len(x) // 2 * 2].reshape(-1, 2).mean(axis=1)          # 16 kHz -> 8 kHz
        x = _mulaw(x / (np.max(np.abs(x)) + 1e-9) * 0.9)
        x = _mix(x, rng.standard_normal(len(x)), LINE_SNR_DB)
    x = np.clip(x, -1, 1)
    return (x * 32767).astype("<i2").tobytes(), LEVELS[level]