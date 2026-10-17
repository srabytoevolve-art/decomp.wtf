"""Build a Master System decompilation exported by decomp.wtf, and check it against your copy of the game.

Every function is assembled at its address with tools/z80.py (decomp.wtf's Z80 assembler, copied here so this
tree builds on its own): src/ holds the functions worked out (assembly, or SDCC's output for C), asm/ the rest as
disassembled from your copy. Everything that isn't code (graphics, sound, maps, tables) is taken from your copy,
baserom.sms, which stays out of git. The result, build/game.sms, must be identical to it.

    python build.py            build and compare
    python build.py <name>     assemble one function and compare it with your copy
"""

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "tools"))
import z80  # noqa: E402


def load():
    return json.loads((HERE / "build.json").read_text(encoding="utf-8"))


# addresses nobody named yet go by their automatic name (D_0000C123, func_00158A3C: bank << 16 | address), as in
# decomp.wtf's judge
AUTO_NAME = re.compile(r"^(?:func|D|B|jtbl|L|RO|STR|FLT|DBL|bss|data|sub|gUnknown|unk|off|dword|word|byte|loc)_"
                       r"([0-9A-Fa-f]{8})$")


def resolver(symbols):
    def resolve(name):
        for n in (name, name[1:] if name.startswith("_") else None):
            if n and n in symbols:
                return symbols[n] & 0xFFFF
            if n and (m := AUTO_NAME.match(n)):
                return int(m.group(1), 16) & 0xFFFF
        return None
    return resolve


def place(fn, symbols, context):
    """The function's bytes, assembled so its label lands at its address."""
    src = (HERE / fn["file"]).read_text(encoding="utf-8")
    sdcc = fn["file"].endswith(".s")
    label = "_" + fn["name"] if sdcc else fn["name"]
    text = src if sdcc or not context else context + "\n" + src
    resolve = resolver(symbols)
    first = z80.assemble(text, 0, lambda n: resolve(n) if resolve(n) is not None else 0, reach=False)
    if label not in first.labels:
        raise SystemExit(f"{fn['file']}: no label {label}")
    start = first.labels[label]
    res = z80.assemble(text, (fn["addr"] - start) & 0xFFFF, resolve)
    end = len(res.code)
    if sdcc:
        later = [at - res.org for name, at in res.labels.items()  # its data and the next function have labels
                 if at - res.org > start and not name.endswith("$") and "." not in name]
        end = min(later, default=end)
    return res.code[start:end]


def main(argv):
    b = load()
    base = HERE / b["image"]
    if not base.exists():
        raise SystemExit(f"put your copy of the game here as {b['image']} first")
    rom = base.read_bytes()
    if hashlib.sha1(rom).hexdigest() != b["sha1"]:
        raise SystemExit(f"{b['image']} isn't the version this tree was made from (sha1 {b['sha1']})")
    context_file = HERE / "include" / "context.inc"
    context = context_file.read_text(encoding="utf-8") if context_file.exists() else ""
    symbols = b["symbols"]
    fns = b["functions"]
    if len(argv) > 1:
        fns = [f for f in fns if f["name"] == argv[1]]
        if not fns:
            raise SystemExit(f"no function {argv[1]} in build.json")
    out = bytearray(rom)  # data comes from your copy; every function is replaced by its assembled source
    bad = []
    for fn in fns:
        try:
            code = place(fn, symbols, context)
        except (z80.AsmError, OSError) as e:
            bad.append(f"{fn['name']}: {e}")
            continue
        off = fn["rom"]
        want = rom[off:off + fn["size"]]
        if code != want:
            first = next((i for i, (x, y) in enumerate(zip(code, want)) if x != y), min(len(code), len(want)))
            bad.append(f"{fn['name']} ({fn['file']}): differs at +${first:X} ({len(code)} bytes, game has {fn['size']})")
            continue
        out[off:off + len(code)] = code
    if len(argv) > 1:
        print("identical" if not bad else bad[0])
        return 0 if not bad else 1
    (HERE / "build").mkdir(exist_ok=True)
    (HERE / "build" / "game.sms").write_bytes(out)
    for line in bad[:30]:
        print(line)
    if not bad and hashlib.sha1(out).hexdigest() == b["sha1"]:
        print(f"build/game.sms: identical to {b['image']} ({len(b['functions'])} functions assembled)")
        return 0
    print(f"build/game.sms differs from {b['image']}: {len(bad)} functions don't assemble to the game's bytes")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
