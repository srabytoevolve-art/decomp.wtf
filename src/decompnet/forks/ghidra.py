"""Ghidra drafts: decompiled C for platforms m2c doesn't read (x86, AArch64, Xbox 360 PowerPC, SuperH...).

Optional: Ghidra is large (540 MB) and needs Java 21+. Headless Ghidra analyses a unit's target object once
and decompiles all its functions; the result is cached next to the project, so the cost (tens of seconds,
mostly starting the JVM) is paid once per source file.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from importlib import resources
from pathlib import Path

from .. import toolchains
from ..limits import capped


def available() -> bool:
    return toolchains.installed("ghidra") is not None and toolchains.java_version() >= 21


def _headless() -> Path:
    base = toolchains.path("ghidra") / "support"
    return base / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")


def decompile_sms(rom: Path, entries: list[tuple[str, int, int, int, str]], out: Path,
                 timeout: float = 3600) -> dict[int, str]:
    """Ghidra's C for a Master System game's functions: vram -> C. `entries` are (kind "f"/"d", bank, address, size,
    name) for the functions and the named data. Written to `out` (JSON) as it's the slow part (a minute or more)."""
    if not available():
        return {}
    with tempfile.TemporaryDirectory(prefix="decompwtf-ghidra-") as tmp:
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        src = resources.files("decompnet.forks").joinpath("ghidra_scripts", "DecompWtfSms.java")
        (scripts / "DecompWtfSms.java").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        program = Path(tmp) / "banks012.bin"
        program.write_bytes(rom.read_bytes()[:0xC000])
        listing = Path(tmp) / "entries.txt"
        listing.write_text("".join(f"{k} {b:x} {a:x} {z:x} {n}\n" for k, b, a, z, n in entries), encoding="utf-8")
        result_file = Path(tmp) / "out.jsonl"
        argv = [str(_headless()), tmp, "decompwtf", "-import", str(program), "-processor", "z80:LE:16:default",
                "-loader", "BinaryLoader", "-loader-baseAddr", "0", "-noanalysis", "-scriptPath", str(scripts),
                "-postScript", "DecompWtfSms.java", str(rom), str(listing), str(result_file), "-deleteProject"]
        try:
            subprocess.run(capped(argv), capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return {}
        result = {}
        if result_file.exists():
            for line in result_file.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                result[int(row["vram"])] = row["c"]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({str(k): v for k, v in result.items()}), encoding="utf-8")
    return result


def decompile_object(obj: Path, cache_dir: Path, timeout: float = 900) -> dict[str, str]:
    """name -> decompiled C for every function in an object file (cached by the object's content)."""
    data = obj.read_bytes()
    key = hashlib.sha1(data).hexdigest()[:16]
    cache = cache_dir / f"{obj.stem}-{key}.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if not available():
        return {}
    with tempfile.TemporaryDirectory(prefix="decompwtf-ghidra-") as tmp:
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        src = resources.files("decompnet.forks").joinpath("ghidra_scripts", "DecompWtfExport.java")
        (scripts / "DecompWtfExport.java").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        out = Path(tmp) / "out.jsonl"
        target = Path(tmp) / obj.name
        shutil.copyfile(obj, target)
        argv = [str(_headless()), tmp, "decompwtf", "-import", str(target), "-scriptPath", str(scripts),
                "-postScript", "DecompWtfExport.java", str(out), "-deleteProject"]
        try:
            subprocess.run(capped(argv), capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return {}
        result = {}
        if out.exists():
            for line in out.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                result[row["name"]] = row["c"]
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(result), encoding="utf-8")
    return result
