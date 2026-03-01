import base64
import re

with open("payload.vbs") as f:
    vbs = f.read()

# Etape 1 : Extraire et decoder le base64 encapsule dans le XML DOM
b64 = re.search(r'A\.text\s*=\s*"([^"]+)"', vbs).group(1)
code = base64.b64decode(b64).decode()


def resolve_chr(text):
    """Resoudre Chr((X*Y)mod 256) et Chr(N) puis concatener"""
    text = re.sub(
        r"Chr\(\((\d+)\*(\d+)\)mod 256\)",
        lambda m: chr((int(m.group(1)) * int(m.group(2))) % 256),
        text,
    )
    text = re.sub(r"Chr\((\d+)\)", lambda m: chr(int(m.group(1))), text)
    text = text.replace('"&"', "").replace('&"', "").replace('"&', "").replace('"', "")
    return text


def decode_layers(code, depth=0):
    """Decoder recursivement les couches Array()+offset mod 256"""
    pattern = r"Array\(([\d,]+)\)\(i\)([\+\*]|xor\s*)(\d+)\)mod 256"
    for match in re.finditer(pattern, code):
        arr = list(map(int, match.group(1).split(",")))
        op = match.group(2).strip()
        val = int(match.group(3))
        if op == "+":
            result = "".join(chr((v + val) % 256) for v in arr)
        elif op == "*":
            result = "".join(chr((v * val) % 256) for v in arr)
        elif op == "xor":
            result = "".join(chr((v ^ val) % 256) for v in arr)
        else:
            continue

        resolved = resolve_chr(result)
        print(f"\n{'=' * 60}")
        print(f"Layer depth={depth} op={op} val={val} len={len(arr)}")
        print(f"{'=' * 60}")
        print(resolved)

        if "Array(" in result:
            decode_layers(result, depth + 1)


decode_layers(code)
