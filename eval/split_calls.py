import pathlib, re, sys

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
out = pathlib.Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
parts = re.split(r"(?m)^===\s*([A-Za-z0-9_]+)\s*===\s*$", raw)
n = 0
for i in range(1, len(parts), 2):
    (out / f"{parts[i]}.txt").write_text(parts[i + 1].strip() + "\n", encoding="utf-8")
    n += 1
print("wrote", n, "files to", out)