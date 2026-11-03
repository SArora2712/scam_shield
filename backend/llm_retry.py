"""Wraps classify_call so a provider rate limit (HTTP 429) waits for the time the provider asks for, then retries."""
import re, time
from . import llm_context


def classify_call(text, tries=5, max_wait=45):
    last = None
    for _ in range(tries):
        try:
            return llm_context.classify_call(text)
        except RuntimeError as e:
            msg = str(e)
            if "429" not in msg:
                raise
            m = re.search(r"try again in (?:(\d+)m)?\s*([0-9.]+)(ms|s)", msg)
            if m:
                wait = int(m.group(1) or 0) * 60 + float(m.group(2)) / (1000 if m.group(3) == "ms" else 1)
            else:
                wait = 5
            if wait > max_wait:
                raise RuntimeError(f"AI rate limit: the provider asks to wait {wait:.0f} s (daily limit?)") from e
            time.sleep(wait + 1.5)
            last = e
    raise last