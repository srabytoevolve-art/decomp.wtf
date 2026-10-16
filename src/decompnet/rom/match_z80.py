"""The judge for Master System functions: put the submission at the function's address and compare the bytes.

Two kinds of source end up here as Z80 assembly: what an agent writes by hand, and what SDCC makes of C. Both are
assembled by decompnet.z80 so the function's label lands at its address in the ROM, with the project's symbols for
everything outside it (other functions, RAM variables, tables).

Assembly always can be written to match, so for hand-written code a match also needs the code to be code:
- bytes the game executes must come from instructions, not `.db`/`.dw` (data directives are fine where the
  function keeps data among its code: a table after a `jp (hl)`, text after a call);
- an address the project has a name for is written as that name (`call PlaySound`, `ld a,(Joypad)`), not as a
  number, so the source reads as the game's logic and survives renames.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import z80
from ..elfobj import FunctionObj
from . import sms
from .symbols import SymbolTable


@dataclass
class Z80Result:
    candidate: FunctionObj | None
    exact: bool
    problems: list[str] = field(default_factory=list)


def _resolver(syms: SymbolTable):
    def resolve(name: str) -> int | None:
        v = syms.resolve(name)
        return None if v is None else v & 0xFFFF
    return resolve


def check_context(context: str) -> str | None:
    """Why a shared asm context can't be used (None: it can): it may hold equates and comments, nothing that
    makes bytes or labels (those would end up inside every function)."""
    try:
        res = z80.assemble(context, 0, lambda n: 0)
    except z80.AsmError as e:
        return f"context: {e}"
    if res.code or res.labels:
        return "context may only hold equates (NAME = value) and comments: no instructions, data or labels"
    return None


def assemble_at(source: str, name: str, addr: int, syms: SymbolTable, context: str = "",
                sdcc: bool = False) -> tuple[z80.Assembled, int, int]:
    """Assemble so the label `name` lands at CPU address `addr`. Returns (result, start, end): the function's
    bytes are result.code[start:end] (for SDCC's output, up to its static data or the next function)."""
    label = f"_{name}" if sdcc else name
    pre = context.count("\n") + 1 if context else 0
    text = f"{context}\n{source}" if context else source
    resolve = _resolver(syms)
    try:
        first = z80.assemble(text, 0, lambda n: resolve(n) if resolve(n) is not None else 0, reach=False)
    except z80.AsmError as e:
        raise z80.AsmError(max(0, e.line - pre), str(e).split(": ", 1)[-1]) from None
    if label not in first.labels:
        raise z80.AsmError(0, f"define the function's label `{label}:` (the judge puts it at ${addr:04X})")
    start = first.labels[label]
    try:
        res = z80.assemble(text, (addr - start) & 0xFFFF, resolve)
    except z80.AsmError as e:
        raise z80.AsmError(max(0, e.line - pre), str(e).split(": ", 1)[-1]) from None
    end = len(res.code)
    if sdcc:  # SDCC writes several functions and their data: this one ends at the next label that isn't its own
        later = [at - res.org for name, at in res.labels.items()  # its data and the next function have labels
                 if at - res.org > start and not name.endswith("$") and "." not in name]
        end = min(later, default=end)
    return res, start, end


def link(source: str, name: str, vram: int, target: bytes, syms: SymbolTable, context: str = "",
         sdcc: bool = False, noreturn: set[int] | None = None, refs: list | None = None) -> Z80Result:
    """Assemble `source` at the function's address and compare with the target bytes. `refs` are the target's
    (offset, kind, vram) references, which say which bank an address in another slot is in."""
    addr = vram & 0xFFFF
    problems: list[str] = []
    if context and not sdcc and (why := check_context(context)):
        return Z80Result(None, False, [why])
    try:
        res, start, end = assemble_at(source, name, addr, syms, context, sdcc)
    except z80.AsmError as e:
        return Z80Result(None, False, [str(e)])
    code = res.code[start:end]
    cand = FunctionObj(name, "z80", False, code, [])
    exact = code == target
    if not sdcc:
        problems += _code_as_data(res, start, end, target, addr, noreturn)
        problems += _numbers_with_names(res, start, end, vram, syms, refs or [])
    return Z80Result(cand, exact and not problems, problems)


def _code_as_data(res: z80.Assembled, start: int, end: int, target: bytes, addr: int, noreturn) -> list[str]:
    """Data directives over bytes the game runs as instructions."""
    insns = sms.code_map(target, addr, noreturn)
    code_bytes = set()
    for off in insns:
        size = z80.decode(target, off, (addr + off) & 0xFFFF).size
        code_bytes.update(range(off, off + size))
    out = []
    for off, size, line in res.data:
        rel = off - start
        if rel + size <= 0 or rel >= end - start:
            continue
        hit = [b for b in range(max(0, rel), min(rel + size, end - start)) if b in code_bytes]
        if hit:
            out.append(f"line {line}: .db/.dw over bytes the game runs as code (offset ${hit[0]:X}): write those "
                       f"as instructions")
    return out


def _numbers_with_names(res: z80.Assembled, start: int, end: int, vram: int, syms: SymbolTable,
                        refs: list) -> list[str]:
    """Addresses written as numbers where the project has a name for them."""
    bank, addr = sms.split_vram(vram)
    out = []
    for off, line, text, value in res.bare:
        if not start <= off < end:
            continue
        if value >= 0xC000 or value < 0x4000:
            candidates = [sms.vram(0, value)]
        elif (value >> 14) == (addr >> 14):
            candidates = [sms.vram(bank, value)]
        else:  # another slot: the bank the game has mapped there, as found when the function was split
            candidates = [t for o, _, t in refs if o == off - start and t & 0xFFFF == value]
        for c in candidates:
            sym = syms.by_addr.get(c)
            if sym is not None:
                out.append(f"line {line}: `{text}` uses ${value:04X}, which has a name: write `{sym.name}`")
                break
    return out
