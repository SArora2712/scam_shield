import io, wave
import numpy as np


def wav_to_pcm(wav_bytes, target_rate=16000):
    """WAV bytes -> raw 16-bit mono little-endian PCM at target_rate."""
    with wave.open(io.BytesIO(wav_bytes)) as w:
        ch, width, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
        raw = w.readframes(w.getnframes())
    if width != 2:
        raise ValueError("expected a 16-bit WAV")
    x = np.frombuffer(raw, dtype="<i2").astype(np.float32)
    if ch > 1:
        x = x.reshape(-1, ch).mean(axis=1)
    if rate != target_rate:
        if rate % target_rate == 0:            # integer downsample: average blocks (crude anti-alias)
            k = rate // target_rate
            x = x[: len(x) // k * k].reshape(-1, k).mean(axis=1)
        else:
            t = np.arange(int(len(x) * target_rate / rate)) * rate / target_rate
            x = np.interp(t, np.arange(len(x)), x)
    return np.clip(x, -32768, 32767).astype("<i2").tobytes()



def pcm_to_wav_bytes(pcm, rate=16000):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    return buf.getvalue()


def split_pcm(pcm, rate=16000, max_s=28, window_s=4):
    """Cut long audio into clips of at most max_s seconds (Gnani REST limit is 30 s),
    cutting at the quietest 0.2 s inside the last window_s seconds of each clip."""
    x = np.frombuffer(pcm, dtype="<i2").astype(np.float32)
    n_max, frame, out, i = int(max_s * rate), int(0.2 * rate), [], 0
    while len(x) - i > n_max:
        lo, hi = i + n_max - int(window_s * rate), i + n_max
        seg = x[lo:hi]
        k = len(seg) // frame
        if k >= 2:
            e = np.sqrt((seg[: k * frame].reshape(k, frame) ** 2).mean(axis=1))
            cut = lo + int(np.argmin(e)) * frame + frame // 2
        else:
            cut = hi
        out.append(x[i:cut])
        i = cut
    out.append(x[i:])
    return [c.astype("<i2").tobytes() for c in out if len(c) > rate * 0.3]