import json
from pathlib import Path

PARENT = Path(__file__).resolve().parent
LIMIT = 10

if __name__ == "__main__":
    lines = (PARENT / "ida.txt").read_text().strip().split("\n")
    lines = lines[1:]  # Headers

    content = []
    i = 0
    for line in lines:
        items = line.split("\t")
        if items[1] == ".text":
            content.append({
                "name": items[0],
                "address": "0x" + items[2].lstrip("0"),
                "size": int(items[3], 16)
            })
            i += 1
        if LIMIT and i == LIMIT:
            break
    (PARENT / "frida.json").write_text(json.dumps(content))
    print("[>] Exported!")
