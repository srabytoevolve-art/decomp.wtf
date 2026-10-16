"""Master System projects in decomp.wtf: import, compile, judge, drafts and splits (the engine calls these).

A project's language follows its compiler: `z80asm` (hand-written assembly, how Master System games were made) or
`sdcc` (C, for homebrew built with devkitSMS). Both end as Z80 assembly that rom.match_z80 judges at the function's
address. Ghidra, when installed, reads every function once in the background; its C is shown to agents as a guide
(and is the starting point for C projects).
"""

from __future__ import annotations

import bisect
import json
import os
import threading
import time
from pathlib import Path

from .. import z80
from ..compiler import MAX_SOURCE_BYTES, CompileResult, compile_source
from . import match_z80, sdcc, sms
from .symbols import Symbol, SymbolTable

ASM_CONTEXT = """\
; Shared context for {title}: every function is assembled after it. Equates (NAME = value) and comments only,
; nothing that makes bytes. Add a constant here (edit_context) the moment several functions need it.

VDP_DATA = $BE          ; video chip: data port
VDP_CONTROL = $BF       ; video chip: address/register writes; reading it returns the status (and acks the IRQ)
VDP_VCOUNTER = $7E      ; read: current scanline
PSG = $7F               ; write: SN76489 sound chip
JOYPAD_1 = $DC          ; read: joypad 1 and half of 2, a 0 bit is a pressed button
JOYPAD_2 = $DD          ; read: the rest of joypad 2, reset button
MEMORY_CONTROL = $3E
IO_CONTROL = $3F
"""

C_CONTEXT_EXTRA = """
/* Master System hardware (SDCC): ports as variables, as devkitSMS declares them */
__sfr __at 0xBE VDPDataPort;
__sfr __at 0xBF VDPControlPort;
__sfr __at 0x7E VDPVCounterPort;
__sfr __at 0x7F PSGPort;
__sfr __at 0xDC IOPortL;
__sfr __at 0xDD IOPortH;
"""

GHIDRA_FILE = "ghidra-c.json"
_ghidra_running: set[str] = set()
_ghidra_lock = threading.Lock()


def lang(cfg: dict) -> str:
    return "c" if cfg.get("compiler", {}).get("toolchain") == "sdcc" else "asm"


def namer(syms: SymbolTable, funcs: list[tuple[int, int, str]]):
    """name_of(vram) for listings: a symbol at that address, or `function+$offset` inside a function."""
    starts = [f[0] for f in funcs]

    def name_of(v: int) -> str | None:
        s = syms.by_addr.get(v)
        if s is not None:
            return s.name
        i = bisect.bisect_right(starts, v) - 1
        if i >= 0 and funcs[i][0] < v < funcs[i][0] + funcs[i][1]:
            return f"{funcs[i][2]}+${v - funcs[i][0]:X}"
        return None
    return name_of


def segments(info: dict) -> list[dict]:
    """Where each bank can be read by vram: bank 0 at 0x0000; the others at slot 1 and at slot 2."""
    out = [{"name": "bank00", "rom_start": 0, "rom_end": min(info["size"], sms.BANK), "vram": 0}]
    for b in range(1, info["banks"]):
        start, end = b * sms.BANK, min(info["size"], (b + 1) * sms.BANK)
        slots = [b] if info.get("mapper") == "none" else [1, 2]
        for slot in slots:
            out.append({"name": f"bank{b:02X}_s{slot}", "rom_start": start, "rom_end": end,
                        "vram": sms.vram(b, slot * sms.BANK)})
    return out


def import_sms(net, picked, slug: str, workdir: Path, toolchain: str | None, flags: list[str] | None, log,
               sym_text: str | None = None, header: str = "") -> str:
    """A Master System game: functions found by following the code (and a .sym file's labels), judged by
    rom.match_z80."""
    info = picked.info
    rom = picked.data
    sym = sms.read_sym(sym_text) if sym_text else {}
    if sym:
        log(f"symbol file: {len(sym)} labels name and seed the functions")
    res = sms.split(rom, sym, log=log)
    toolchain = toolchain or ("sdcc" if info["compiler_guess"] == "SDCC" else "z80asm")
    compiler = {"toolchain": toolchain, "flags": flags or [], "timeout": 20}
    if toolchain == "sdcc":
        compiler["version"] = sdcc.version()
        if compiler["version"] is None:
            log("this looks like SDCC homebrew, but SDCC isn't installed: install it to compile C (see Setup)")
    else:
        log("functions are written in Z80 assembly that must assemble to the game's bytes (decomp.wtf's assembler)")
    cfg = {
        "kind": "rom", "platform": "sms", "big_endian": False, "gp": 0, "arch": "z80",
        "rom": {**info, "file": picked.filename, "program": picked.filename},
        "segments": segments(info),
        "compiler": compiler,
        "sms": {"noreturn": res.noreturn, "switchers": {str(k): v for k, v in res.switchers.items()},
                "symbol_file": bool(sym)},
        "legal": {"basis": "personal-copy", "license": "personal use only",
                  "statement": "imported by the owner of this copy of the game, who confirmed it was legally obtained",
                  "confirmed_at": time.time()},
        "context": {"file": None},
    }
    syms = SymbolTable()
    names: set[str] = set()
    funcs = []
    for f in res.functions:
        name = f.name if f.name not in names else f"{f.name}_{f.vram:08X}"
        names.add(name)
        f.name = name
        syms.add(Symbol(name, f.vram, len(f.code), "func"), reindex=False)
        funcs.append((f.vram, len(f.code), name))
    for addr, label in sms.MAPPER.items():
        syms.add(Symbol(label, addr, 1, "data"), reindex=False)
    for v, size in sorted(res.data.items()):
        if v not in syms.by_addr:
            syms.add(Symbol(sym.get(v) or f"D_{v:08X}", v, size, "data"), reindex=False)
    for v, label in sym.items():  # the symbol file's other labels (RAM, tables) name data
        if v not in syms.by_addr and label not in syms.by_name:
            syms.add(Symbol(label, v, 0, "data"), reindex=False)
    syms._reindex()
    name_of = namer(syms, funcs)
    context = (ASM_CONTEXT.format(title=info["title"]) if toolchain == "z80asm"
               else header.format(title=info["title"]) + C_CONTEXT_EXTRA)
    now = time.time()
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,name,description,arch,big_endian,root,config) VALUES(?,?,?,?,?,?,?)",
                         (slug, info["title"], f"{info['system']} · {info['region']} · {len(res.functions)} functions",
                          "z80", 0, str(workdir), json.dumps(cfg))).lastrowid
        for f in res.functions:
            text = sms.listing(f.name, f.vram, f.code, f.refs, name_of, f.insns)
            db.execute(
                "INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset,status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, f.name, len(f.code), f.n_insns, f.code, json.dumps([list(r) for r in f.refs]), text, None,
                 f"bank{f.vram >> 16:02X}", f.vram, f.rom, "open"))
        for s in syms.by_name.values():
            db.execute("INSERT INTO symbols(project_id,name,address,size,kind,preview) VALUES(?,?,?,?,?,?)",
                       (pid, s.name, s.address, s.size, s.kind, None))
        db.execute("INSERT INTO context_versions(project_id,version,header,agent_id,message,created_at,unit) "
                   "VALUES(?,?,?,?,?,?,?)", (pid, 1, context, None, "hardware ports", now, ""))
        net._event(db, pid, None, "import", f"{len(res.functions)} functions from {info['title']}")
    log(f"ready: {len(res.functions)} functions to decompile")
    start_ghidra(net, slug, log)
    return slug


# ------------------------------------------------------------------------------------------ compile & judge

def compile_source_sms(net, proj, header: str, source: str) -> CompileResult:
    """The "object" handed to the judge: the Z80 assembly to place (as JSON, with what it needs)."""
    cfg = net.cfg(proj)
    if len(source.encode()) > MAX_SOURCE_BYTES:
        return CompileResult(False, None, f"rejected: source too large (max {MAX_SOURCE_BYTES} bytes)")
    if lang(cfg) == "c":
        try:
            cc = sdcc.config(cfg["compiler"].get("flags", []), float(cfg["compiler"].get("timeout", 20)))
        except Exception as e:  # SDCC missing
            return CompileResult(False, None, str(e))
        res = compile_source(cc, header, source)
        if not res.ok:
            return res
        asm = res.obj.decode("utf-8", "replace")
        return CompileResult(True, json.dumps({"lang": "c", "source": asm}).encode(), res.log)
    if (why := match_z80.check_context(header)):
        return CompileResult(False, None, why)
    syms = net.symbols(proj["id"])

    def resolve(name):
        v = syms.resolve(name)
        return None if v is None else v & 0xFFFF
    try:  # a branch's reach depends on where it's placed: the judge checks that
        z80.assemble(f"{header}\n{source}", 0, resolve, reach=False)
    except z80.AsmError as e:
        line = max(0, e.line - header.count("\n") - 1)
        return CompileResult(False, None, f"line {line}: {str(e).split(': ', 1)[-1]}" if line else str(e))
    return CompileResult(True, json.dumps({"lang": "asm", "source": source, "context": header}).encode(), "")


def evaluate(net, fn, proj, obj: bytes):
    """(candidate, verdict, problems) for the engine."""
    payload = json.loads(obj)
    cfg = net.cfg(proj)
    refs = [tuple(r) for r in json.loads(fn["relocs"])]
    noreturn = set(cfg.get("sms", {}).get("noreturn", []))
    nr_calls = {o for o, k, t in refs if k == 10 and t in noreturn}
    res = match_z80.link(payload["source"], fn["name"], fn["vram"], fn["target"], net.symbols(proj["id"]),
                         payload.get("context", ""), sdcc=payload["lang"] == "c", noreturn=nr_calls, refs=refs)
    return res.candidate, (res.exact if res.candidate is not None else None), res.problems


# --------------------------------------------------------------------------------------------- drafts

def ghidra_c(proj) -> dict[int, str] | None:
    path = Path(proj["root"]) / GHIDRA_FILE
    if not path.exists():
        return None
    try:
        return {int(k): v for k, v in json.loads(path.read_text(encoding="utf-8")).items()}
    except (OSError, ValueError):
        return None


def start_ghidra(net, slug: str, log=print) -> bool:
    """Ghidra's C for every function, in the background (a minute or more): drafts pick it up when it's there."""
    from ..forks import ghidra

    if os.environ.get("DECOMP_GHIDRA_DRAFTS") == "off" or not ghidra.available():
        return False
    with _ghidra_lock:
        if slug in _ghidra_running:
            return True
        _ghidra_running.add(slug)
    proj = net._project(slug)
    rows = net.store.all("SELECT name, vram, size FROM functions WHERE project_id=?", proj["id"])
    entries = [("f", r["vram"] >> 16, r["vram"] & 0xFFFF, r["size"], r["name"]) for r in rows]
    entries += [("d", 0, s.address & 0xFFFF, 0, s.name) for s in net.symbols(proj["id"]).by_name.values()
                if s.kind != "func" and (s.address & 0xFFFF) >= 0xC000]
    rom_path = Path(proj["root"]) / net.cfg(proj)["rom"]["file"]
    log("Ghidra is reading the game in the background (its C helps agents understand the assembly)")

    def run():
        try:
            ghidra.decompile_sms(rom_path, entries, Path(proj["root"]) / GHIDRA_FILE)
            with net.store.tx() as db:  # drafts made before Ghidra finished get its C next time
                db.execute("UPDATE functions SET seed=NULL WHERE project_id=? AND status='open'", (proj["id"],))
        finally:
            with _ghidra_lock:
                _ghidra_running.discard(slug)

    threading.Thread(target=run, name=f"ghidra-{slug}", daemon=True).start()
    return True


def seed(net, fn, proj) -> str | None:
    """The starting point: for assembly, the function's listing (it assembles already) under Ghidra's C as
    comments; for C, Ghidra's C."""
    cfg = net.cfg(proj)
    cs = ghidra_c(proj)
    c = cs.get(fn["vram"]) if cs else None
    if cs is None:
        start_ghidra(net, proj["slug"], log=lambda *_: None)
    if lang(cfg) == "asm":
        text = net._asm_text(fn, proj)
        if c:
            text = ("; Ghidra's reading of this function, to help understand it (not assembled):\n"
                    + "".join(f";   {ln}\n" for ln in c.strip().splitlines()) + ";\n" + text)
    else:
        if not c:
            return None
        text = f"/* Ghidra's reading of the machine code: a starting point, not a match */\n{c.strip()}\n"
    with net.store.tx() as db:
        db.execute("UPDATE functions SET seed=? WHERE id=?", (text, fn["id"]))
    return text


def brief_lines(net, fn, proj) -> list[str]:
    """For assembly projects, Ghidra's C next to the listing in an agent's brief."""
    if lang(net.cfg(proj)) != "asm":
        return []
    cs = ghidra_c(proj)
    c = cs.get(fn["vram"]) if cs else None
    if not c:
        return []
    return ["", "### Ghidra's reading (C), to understand the assembly", "```c", c.strip(), "```"]


# ---------------------------------------------------------------------------------------------- splits

def split(net, agent, proj, fn, addr: int, new_name: str, syms: SymbolTable) -> str:
    """Cut a function in two at `addr`, or, past its end, make the code there a new function."""
    from ..network import NetworkError

    if addr >> 16 != fn["vram"] >> 16:
        raise NetworkError(f"0x{addr:08X} is in another bank than {fn['name']} (bank {fn['vram'] >> 16:#x})")
    off = addr - fn["vram"]
    rom, _ = net._rom(proj)
    lay = sms.layout(rom)
    if off >= fn["size"]:
        nxt = net.store.one("SELECT vram FROM functions WHERE project_id=? AND vram>? ORDER BY vram LIMIT 1",
                            proj["id"], addr)
        bank, cpu = sms.split_vram(addr)
        slot_end = (cpu & ~(sms.BANK - 1)) + sms.BANK
        limit = (min(nxt["vram"] & 0xFFFF, slot_end) if nxt and nxt["vram"] >> 16 == bank else slot_end) - cpu
        if not lay.valid(addr) or not sms.plausible_code(rom, lay, addr):
            raise NetworkError(f"0x{addr:08X} doesn't look like the start of a function")
        window = rom[sms.rom_offset(addr):sms.rom_offset(addr) + max(0, limit)]
        insns = sms.code_map(window, cpu)
        last = max(insns)
        code = window[:last + z80.decode(window, last, (cpu + last) & 0xFFFF).size]
        refs = sms.simple_refs(code, addr, insns, lay)
        _insert(net, agent, proj, fn, new_name, addr, code, refs, insns, syms, sms.rom_offset(addr))
        return f"✅ new function {new_name} at 0x{addr:08X}, {len(code)} bytes."
    if off <= 0:
        raise NetworkError(f"0x{addr:08X} isn't inside {fn['name']} (0x{fn['vram']:08X}, {fn['size']} bytes)")
    target = fn["target"]
    head, tail = target[:off], target[off:]
    refs = [tuple(r) for r in json.loads(fn["relocs"])]
    head_refs = [r for r in refs if r[0] < off]
    tail_refs = [(r[0] - off, r[1], r[2]) for r in refs if r[0] >= off]
    head_insns = sms.code_map(head, fn["vram"] & 0xFFFF)
    syms.add(Symbol(new_name, addr, len(tail), "func"))
    old = syms.by_name.get(fn["name"])
    if old is not None:
        old.size = len(head)
    name_of = namer(syms, _funcs(net, proj, syms))
    with net.store.tx() as db:
        db.execute("UPDATE functions SET size=?, n_insns=?, target=?, relocs=?, asm=?, seed=NULL, best_score=NULL "
                   "WHERE id=?", (len(head), max(1, len(head_insns)), head, json.dumps([list(r) for r in head_refs]),
                                  sms.listing(fn["name"], fn["vram"], head, head_refs, name_of, head_insns), fn["id"]))
        db.execute("UPDATE symbols SET size=? WHERE project_id=? AND name=?", (len(head), proj["id"], fn["name"]))
    tail_insns = sms.code_map(tail, addr & 0xFFFF)
    _insert(net, agent, proj, fn, new_name, addr, tail, tail_refs, tail_insns, syms, fn["rom_offset"] + off)
    return (f"✅ split: {fn['name']} is now {len(head)} bytes; {new_name} at 0x{addr:08X} has {len(tail)}. "
            f"Continue with {fn['name']} (get_function shows its new assembly).")


def _funcs(net, proj, syms: SymbolTable) -> list[tuple[int, int, str]]:
    rows = net.store.all("SELECT name, vram, size FROM functions WHERE project_id=? ORDER BY vram", proj["id"])
    return [(r["vram"], r["size"], r["name"]) for r in rows]


def _insert(net, agent, proj, prev, name: str, addr: int, code: bytes, refs, insns, syms: SymbolTable,
            rom_offset: int) -> None:
    syms.add(Symbol(name, addr, len(code), "func"))
    funcs = sorted(_funcs(net, proj, syms) + [(addr, len(code), name)])
    text = sms.listing(name, addr, code, refs, namer(syms, funcs), insns)
    with net.store.tx() as db:
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (proj["id"], name, len(code), max(1, len(insns)), code,
                                                    json.dumps([list(r) for r in refs]), text, None,
                                                    f"bank{addr >> 16:02X}", addr, rom_offset))
        db.execute("INSERT OR REPLACE INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                   (proj["id"], name, addr, len(code), "func"))
        net._event(db, proj["id"], agent.id, "split", f"{prev['name']} / {name}")
    net._xrefs.pop(proj["id"], None)
    net._ops.pop(proj["id"], None)
