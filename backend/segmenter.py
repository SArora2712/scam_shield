
import re

_PLACEHOLDER = re.compile(r"\[([^\]]*)\]")
_KEEP = {
    "money": "money",
    "number": "account number",
    "link": "link",
    "apk file": "apk file"
}


def clean(text):
    """Drop dataset placeholders like [Name] / [Greetings]; keep meaningful ones."""
    text = _PLACEHOLDER.sub(
        lambda m: _KEEP.get(m.group(1).strip().lower(), ""),
        text
    )
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+([,.!?])", r"\1", text)
    return re.sub(r"(^|(?<=[.!?]) )[,;:\s]+", r"\1", text)


def split_segments(text, short=18, max_words=28):
    """One long paragraph -> sentence-sized segments, matched and scored in order."""
    text = clean(text)

    if len(text.split()) <= short:
        return [text] if text else []

    out = []
    final = []

    for s in re.split(r"(?<=[.!?])\s+", text):
        s = s.strip()

        if not s:
            continue

        if len(s.split()) <= max_words:
            out.append(s)
            continue

        buf = ""

        for p in re.split(r"[;,]\s+", s):
            buf = f"{buf}, {p}" if buf else p

            if len(buf.split()) >= 8:
                out.append(buf)
                buf = ""

        if buf:
            if out:
                out[-1] += ", " + buf
            else:
                out.append(buf)

    for piece in out:
        w = piece.split()

        if len(w) <= max_words:
            final.append(piece)

        else:
            # Overlapping word windows when punctuation is unavailable
            step = 10

            for i in range(0, len(w), step):
                chunk = w[i:i + 14]

                if len(chunk) >= 5 or not final:
                    final.append(" ".join(chunk))

                if i + 14 >= len(w):
                    break

    return [x for x in final if len(x.split()) >= 3]
