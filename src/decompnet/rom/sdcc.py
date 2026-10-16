"""SDCC, the C compiler of Master System homebrew (devkitSMS), for the C side of SMS projects.

SDCC only goes as far as Z80 assembly here (`-S`): decompnet.z80 assembles that at the function's address, the
same as hand-written code, so one judge covers both. Where SDCC comes from: decomp.wtf's own copy when it's
installed (`decompnet toolchain install sdcc`, Linux and macOS), else one already on this computer (PATH, SDCC's
Windows installer, MSYS2's mingw-w64-x86_64-sdcc).
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .. import toolchains
from ..compiler import CompilerConfig


def find() -> Path | None:
    own = toolchains.path("sdcc") / "bin" / ("sdcc.exe" if os.name == "nt" else "sdcc")
    if (toolchains.path("sdcc") / toolchains.MANIFEST).exists() and own.exists():
        return own
    return toolchains.system_exe("sdcc")


def version(exe: Path | None = None) -> str | None:
    exe = exe or find()
    if exe is None:
        return None
    try:
        out = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=20,
                             encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"\b(\d+\.\d+\.\d+)\b", out.stdout + out.stderr)
    return m.group(1) if m else None


def config(flags: list[str], timeout: float = 20) -> CompilerConfig:
    exe = find()
    if exe is None:
        raise toolchains.ToolchainError(
            "SDCC isn't installed: install it from https://sdcc.sourceforge.net (Windows: the installer, or MSYS2's "
            "`pacman -S mingw-w64-x86_64-sdcc`), or run `decompnet toolchain install sdcc` on Linux and macOS")
    env = dict(os.environ)
    env["PATH"] = str(exe.parent) + os.pathsep + env.get("PATH", "")  # sdcc runs sdcpp (its preprocessor) from PATH
    return CompilerConfig(cmd=[str(exe), "-mz80", "-S", "--no-std-crt0", *flags, "-I{include}", "{src}", "-o", "{obj}"],
                          timeout=timeout, sandbox="none" if os.name == "nt" else "auto",
                          ro_paths=(str(exe.parent.parent),), env=env)
