"""Export a Master System project as a source tree that rebuilds the game: the base for ports and mods.

Matched functions are the agents' assembly (or C with the assembly SDCC made of it) in src/; the rest is the
disassembly with the project's names in asm/ (made from your copy, so it stays out of git, like the ROM). build.py
assembles every function at its address with a copy of decomp.wtf's assembler and checks the ROM it makes against
yours, byte for byte.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from ..limits import capped
from . import sms_project


def export_sms(net, slug: str, out: Path, log=print) -> dict:
    proj = net._project(slug)
    cfg = net.cfg(proj)
    work = Path(proj["root"])
    image = (work / cfg["rom"]["file"]).read_bytes()
    if out.exists():
        for child in out.iterdir():
            if child.name != ".git":
                shutil.rmtree(child) if child.is_dir() else child.unlink()
    for d in ("src", "asm", "include", "tools"):
        (out / d).mkdir(parents=True, exist_ok=True)
    lang = sms_project.lang(cfg)
    ctx = net._context(proj["id"])["header"]
    if lang == "asm":
        (out / "include" / "context.inc").write_text(ctx, encoding="utf-8")
    else:
        (out / "include" / "common.h").write_text(ctx, encoding="utf-8")

    rows = net.store.all("SELECT * FROM functions WHERE project_id=? ORDER BY rom_offset, vram", proj["id"])
    syms = net.symbols(proj["id"])
    functions, fallback, taken = [], [], set()
    log("writing the functions: matched ones as their source, the rest as disassembly")
    for row in rows:
        span = range(row["rom_offset"], row["rom_offset"] + row["size"])
        if any(b in taken for b in (span.start, span.stop - 1)):
            continue  # the same bytes reached at a second address (a bank seen in two slots): one is enough
        taken.update(span)
        f = {"name": row["name"], "addr": row["vram"] & 0xFFFF, "bank": row["vram"] >> 16, "rom": row["rom_offset"],
             "size": row["size"]}
        source = row["matched_source"] if row["status"] == "matched" else None
        if source and lang == "c":
            compiled = net._compile(proj, net._context(proj["id"], row["unit"])["header"], source)
            if compiled.ok:
                (out / "src" / f"{row['name']}.c").write_text(f'#include "common.h"\n\n{source.strip()}\n', encoding="utf-8")
                (out / "src" / f"{row['name']}.s").write_text(json.loads(compiled.obj)["source"], encoding="utf-8")
                f["file"] = f"src/{row['name']}.s"
            else:
                fallback.append((row["name"], "doesn't compile any more"))
        elif source:
            (out / "src" / f"{row['name']}.asm").write_text(source.strip() + "\n", encoding="utf-8")
            f["file"] = f"src/{row['name']}.asm"
        if "file" not in f:
            (out / "asm" / f"{row['name']}.asm").write_text(net._asm_text(row, proj), encoding="utf-8")
            f["file"] = f"asm/{row['name']}.asm"
        functions.append(f)

    build = {"title": proj["name"], "platform": "sms", "image": "baserom.sms", "output": "build/game.sms",
             "sha1": hashlib.sha1(image).hexdigest(), "language": lang, "functions": functions,
             "symbols": {s.name: s.address for s in sorted(syms.by_name.values(), key=lambda s: s.address)}}
    (out / "build.json").write_text(json.dumps(build, indent=1), encoding="utf-8")
    shutil.copyfile(Path(__file__).with_name("export_sms_build.py"), out / "build.py")
    shutil.copyfile(Path(__file__).resolve().parent.parent / "z80.py", out / "tools" / "z80.py")
    shutil.copyfile(work / cfg["rom"]["file"], out / "baserom.sms")
    matched = sum(1 for f in functions if f["file"].startswith("src/"))
    _docs(out, proj["name"], matched, len(functions), fallback, lang)
    (out / ".gitignore").write_text("build/\nbaserom*\nasm/\n", encoding="utf-8")

    log("building the exported project to check it rebuilds the game byte for byte")
    proc = subprocess.run(capped([sys.executable, "build.py"]), cwd=out, capture_output=True, text=True, timeout=3600,
                          encoding="utf-8", errors="replace")
    identical = proc.returncode == 0 and "identical" in proc.stdout
    if not identical:
        log((proc.stdout + proc.stderr)[-3000:])
    return {"path": str(out), "identical": identical, "matched": matched, "functions": len(functions),
            "fallback": fallback, "language": lang, "log": (proc.stdout + proc.stderr)[-3000:]}


def _docs(out: Path, title: str, matched: int, total: int, fallback, lang: str) -> None:
    notes = "".join(f"\n- `{n}`: kept as disassembly, {why}" for n, why in fallback)
    what = ("assembly source that assembles to exactly the original code" if lang == "asm" else
            "C that SDCC compiles to exactly the original code")
    (out / "README.md").write_text(f"""# {title} (decompilation)

A matching decompilation of {title} for the Sega Master System, started with [decomp.wtf](https://decomp.wtf).
{matched} of {total} functions are {what}; the rest is disassembly with the project's names.
`build.py` assembles every function at its address and checks the ROM against your original, byte for byte.

## Build

1. Put your own copy of the game here as `baserom.sms` (it is in `.gitignore`; never commit it).
2. `python build.py` (Python 3.10+; nothing else: `tools/z80.py` is the assembler).

## Layout

| Path | What it is |
| :-- | :-- |
| `src/<function>.asm` | Functions worked out: named, labelled, commented, and still matching. |
| `src/<function>.c`, `.s` | (C projects) the C, and the assembly SDCC made of it, which the build uses. |
| `asm/<function>.asm` | Everything else, disassembled from your copy (not committed). |
| `include/context.inc` | Shared constants (hardware ports and what agents added). |
| `build.json`, `build.py` | Where every function goes, every name's address, and the build. |

Graphics, sound, maps and tables are taken from your copy as they are. To keep going, move a function from `asm/`
to `src/`, improve it, point its entry in `build.json` at the new file and run `python build.py <name>`.

The game's code and data belong to their rights holder: keep this tree to yourself unless you have the right to
share it.{chr(10) + chr(10) + '## Notes' + notes if notes else ''}
""", encoding="utf-8")
    (out / "AGENTS.md").write_text("""# Working on this decompilation

- Goal: source that assembles to exactly the original bytes. `python build.py` must end with "identical".
- Pick a function from `asm/`, move it to `src/`, give it and what it uses real names, comment it, and check it
  with `python build.py <name>`. Names live in `build.json` ("symbols"): rename there and in the sources together.
- Never edit `baserom.sms`, and don't replace code with `.db` bytes to force a match.
""", encoding="utf-8")
