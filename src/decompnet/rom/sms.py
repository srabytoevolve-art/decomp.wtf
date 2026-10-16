"""Sega Master System (and Game Gear) ROMs: header, banks, and finding the functions.

Addresses: the Z80 sees 64 KiB. The cartridge's Sega mapper shows 16 KiB banks of the ROM in three slots (0x0000,
0x4000, 0x8000; bank 0's first KiB is always at 0x0000), and code switches banks by writing their number to
0xFFFE (slot 1) or 0xFFFF (slot 2). So a function is named by its bank and the address it runs at:
`func_00158A3C` is bank 0x15 running at 0x8A3C, and its address in decomp.wtf ("vram") is 0x00158A3C. RAM
(0xC000-0xDFFF, mirrored at 0xE000) has bank 0: `D_0000C100`.

Finding the functions: from the reset, interrupt and pause entry points the code is followed instruction by
instruction, calls and jumps included, keeping track of the banks it maps (`ld a,5 / ld ($FFFF),a`, and calls to
functions that map the bank passed in A). Three more passes repeat that until nothing new turns up:
- functions that never return (a jump-table dispatcher ends in `jp (hl)`), so the bytes after a call to one aren't
  taken for code;
- tables of code addresses that code points at (`ld hl,table / rst $20`);
- a WLA-DX symbol file (`game.sym` next to `game.sms`), when there is one: emulators and disassemblers write them,
  and their labels name and seed what the code alone can't reach (banks chosen by a number kept in RAM).
What's still unreached stays data until an agent finds a function in it (split_function).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import z80
from .n64 import RomError

BANK = 0x4000
HEADER_AT = (0x7FF0, 0x3FF0, 0x1FF0)
SYSTEMS = {3: "Master System (Japan)", 4: "Master System", 5: "Game Gear (Japan)", 6: "Game Gear", 7: "Game Gear"}
SIZES = {0xA: 8 << 10, 0xB: 16 << 10, 0xC: 32 << 10, 0xD: 48 << 10, 0xE: 64 << 10, 0xF: 128 << 10, 0x0: 256 << 10,
         0x1: 512 << 10, 0x2: 1 << 20}
MAPPER = {0xFFFC: "MAPPER_CONTROL", 0xFFFD: "MAPPER_SLOT0", 0xFFFE: "MAPPER_SLOT1", 0xFFFF: "MAPPER_SLOT2"}


def vram(bank: int, addr: int) -> int:
    return (bank << 16) | (addr & 0xFFFF)


def split_vram(v: int) -> tuple[int, int]:
    return v >> 16, v & 0xFFFF


def rom_offset(v: int) -> int:
    bank, addr = split_vram(v)
    return bank * BANK + (addr & (BANK - 1))


def header_at(data: bytes) -> int | None:
    for at in HEADER_AT:
        if len(data) >= at + 16 and data[at:at + 8] == b"TMR SEGA":
            return at
    return None


def is_sms(data: bytes, name: str = "") -> bool:
    """A Master System or Game Gear ROM: the `TMR SEGA` header (every export game and the BIOS checks it), or for
    Japanese games without one, the file name and a cartridge-sized file that starts with code."""
    if header_at(data) is not None:
        return True
    ext = Path(name).suffix.lower()
    return (ext in (".sms", ".gg", ".sg") and len(data) >= 8 << 10 and len(data) % (8 << 10) in (0, 512)
            and data[0] in (0xF3, 0xC3, 0x31, 0xED, 0x18, 0x00))


def strip_copier_header(data: bytes) -> bytes:
    """Some dumps carry a 512-byte copier header in front: the game starts after it."""
    return data[512:] if len(data) % (8 << 10) == 512 else data


def _sdsc(data: bytes) -> dict:
    """The SDSC header homebrew made with devkitSMS/WLA-DX carries: version, date, author, name, description."""
    if len(data) < 0x7FF0 or data[0x7FE0:0x7FE4] != b"SDSC":
        return {}

    def text(ptr_at: int) -> str:
        ptr = int.from_bytes(data[ptr_at:ptr_at + 2], "little")
        if ptr in (0, 0xFFFF) or ptr >= len(data):
            return ""
        return data[ptr:data.index(b"\0", ptr) if b"\0" in data[ptr:ptr + 256] else ptr + 64].decode("latin-1").strip()

    bcd = lambda b: (b >> 4) * 10 + (b & 15)  # noqa: E731
    return {"sdsc_version": f"{bcd(data[0x7FE4])}.{bcd(data[0x7FE5]):02}", "author": text(0x7FEA),
            "name": text(0x7FEC), "description": text(0x7FEE)}


def read_info(data: bytes, name: str = "") -> dict:
    if not is_sms(data, name):
        raise RomError("this isn't a Master System or Game Gear ROM")
    at = header_at(data)
    sdsc = _sdsc(data)
    region = system = ""
    code = ""
    version = 0
    if at is not None:
        h = data[at:at + 16]
        code = f"{h[0xE] >> 4:X}{h[0xD]:02X}{h[0xC]:02X}".lstrip("0") or "0"
        version = h[0xE] & 0xF
        system = SYSTEMS.get(h[0xF] >> 4, "Master System")
        region = {3: "Japan", 5: "Japan"}.get(h[0xF] >> 4, "Export")
    if not system:
        system = "Game Gear" if Path(name).suffix.lower() == ".gg" else "Master System"
        region = "Japan"
    title = sdsc.get("name") or Path(name).stem or f"Master System {code}"
    homebrew = bool(sdsc) or _looks_sdcc(data)
    return {"title": title, "game_code": code, "region": region, "version": version, "size": len(data),
            "sha1": hashlib.sha1(data).hexdigest(), "entrypoint": 0, "platform": "sms", "system": system,
            "byte_order": "sms", "compiler_guess": "SDCC" if homebrew else "Z80 assembly", "gp": 0,
            "mapper": "sega" if len(data) > 48 << 10 else "none", "banks": (len(data) + BANK - 1) // BANK,
            "header": at, **({"sdsc": sdsc} if sdsc else {})}


def _looks_sdcc(data: bytes) -> bool:
    """SDCC's crt0 for the SMS (devkitSMS) and its runtime leave recognisable code: the `___sdcc_call_hl` thunk
    (`jp (hl)`) right after a `ret`-heavy runtime is too common, so look for devkitSMS's own names in the ROM."""
    return b"devkitSMS" in data or b"SMSlib" in data


# ---------------------------------------------------------------------------------------------- the layout

@dataclass
class Layout:
    """Which bank is where. Without a mapper (48 KiB or less) the ROM is simply at 0x0000-0xBFFF."""
    size: int
    mapper: bool

    @property
    def banks(self) -> int:
        return (self.size + BANK - 1) // BANK

    def bank_of(self, addr: int, s1: int | None, s2: int | None) -> int | None:
        """The bank at CPU address `addr` when slots 1 and 2 hold s1 and s2 (None: not known), or None for RAM."""
        if addr < 0x4000:
            return 0
        if addr < 0x8000:
            return 1 if not self.mapper else s1
        if addr < 0xC000:
            return 2 if not self.mapper else s2
        return None

    def valid(self, v: int) -> bool:
        bank, addr = split_vram(v)
        if addr >= 0xC000 or bank >= self.banks or rom_offset(v) >= self.size:
            return False
        if not self.mapper:
            return bank == addr >> 14
        return (bank == 0) == (addr < 0x4000)  # bank 0 sits in slot 0; the others in slot 1 or 2


def layout(data: bytes) -> Layout:
    return Layout(len(data), len(data) > 48 << 10)


# ---------------------------------------------------------------------------------------- following the code

_WRITES_A = re.compile(r"^(?:ld a,|in a,|inc a$|dec a$|add a,|adc a,|sub |sbc a,|and |xor |or |rlca|rrca|rla|rra|"
                       r"cpl|neg|daa|pop af|ex af|rlc a|rrc a|rl a|rr a|sla a|sra a|sll a|srl a|res \d,a|set \d,a|"
                       r"ld\.\w+ a,|in\.\w+ a,|ld a,i|ld a,r)")
_WRITES_HL = re.compile(r"^(?:ld hl,|ld h,|ld l,|pop hl|ex de,hl|exx|add hl,|adc hl,|sbc hl,|ex \(sp\),hl|"
                        r"inc h$|dec h$|inc l$|dec l$|ld\.\w+ hl,|ldi|ldd|ldir|lddr|cpi|cpd|cpir|cpdr|ini|ind|inir|"
                        r"indr|outi|outd|otir|otdr|rlc h|rlc l|rl h|rl l|rr h|rr l|sla h|sla l|srl h|srl l)")
ARG = "arg"  # A as the function was entered with it (to find functions that map the bank passed in A)
_SELF_LOADS = {0x40, 0x49, 0x52, 0x5B, 0x64, 0x6D, 0x7F}  # ld b,b ... ld a,a: graphics, rarely code


def _ram(x) -> bool:
    return isinstance(x, tuple) and x[0] == "ram"


@dataclass
class State:
    """What's known at a point in the code: the banks in slots 1 and 2 (a number, ("var", ram address) when it
    came from a bank variable, or None) and the values of A and HL."""
    s1: object
    s2: object
    a: object = None  # int, ARG, ("ram", address it was loaded from) or None
    hl: int | None = None

    def copy(self) -> "State":
        return State(self.s1, self.s2, self.a, self.hl)


@dataclass
class Found:
    """What following the code found."""
    starts: dict[int, str] = field(default_factory=dict)  # function vram -> how it was found
    mapping: dict[int, tuple] = field(default_factory=dict)  # function vram -> (s1, s2) it was traced with
    entered: dict[int, set] = field(default_factory=dict)  # function vram -> every (s1, s2) it's entered with
    noreturn: set[int] = field(default_factory=set)
    inline: set[int] = field(default_factory=set)  # dispatchers whose calls are followed by a table
    switchers: dict[int, int] = field(default_factory=dict)  # function vram -> slot it maps from A (1 or 2)
    bank_vars: dict[int, int] = field(default_factory=dict)  # RAM address -> slot its value is mapped into
    ram_consts: dict[int, set] = field(default_factory=dict)  # RAM address -> constants the code stores there
    refs: dict[int, list] = field(default_factory=dict)  # insn vram -> [(kind, target vram)]
    insns: dict[int, z80.Insn] = field(default_factory=dict)  # insn vram -> instruction
    state_at: dict[int, tuple] = field(default_factory=dict)  # insn vram -> (s1, s2)
    data: dict[int, int] = field(default_factory=dict)  # data vram -> size (RAM variables, ROM tables)
    names: dict[int, str] = field(default_factory=dict)  # from a .sym file


def _decode(rom: bytes, lay: Layout, v: int) -> z80.Insn | None:
    if not lay.valid(v):
        return None
    bank, addr = split_vram(v)
    off = rom_offset(v)
    end = min(len(rom), bank * BANK + BANK)
    return z80.decode(rom[off:min(end, off + 4)], 0, addr)


_ODD_START = re.compile(r"^(?:nop|ld \(bc\),a|ld \(de\),a|ex af|halt|rst|daa|ccf|scf|ret [pm]|ret p[oe]|di|ei)")
_ODD = re.compile(r"^(?:nop|ld \(bc\),a|ex af|halt|daa|ccf|(?:ret|jp|call) (?:p|m|po|pe)\b|in |out \(c\)|ld [ir],a|"
                  r"ld a,[ir]|neg|rrd|rld|im |reti|retn)")


def plausible_code(rom: bytes, lay: Layout, v: int, limit: int = 48, strict: bool = False) -> bool:
    """Whether code starting at `v` reads like a function: real instructions up to a ret or jump, without what
    graphics and filler decode to (`rst $38` = $FF, `ld b,b`...). `strict`, for addresses that are only guesses
    (words in a table, a bank picked from a variable): also not what tables of records decode to, which starts
    with or soon has `nop`, `ld (bc),a`, `ret m`..."""
    if not lay.valid(v):
        return False
    off = rom_offset(v)
    if rom[off] in (0xFF, 0x00) and rom[off + 1:off + 2] in (bytes([rom[off]]), b""):
        return False
    odd = 0
    for seen in range(limit):
        ins = _decode(rom, lay, v)
        if ins is None or ins.op is None or (seen == 0 and ins.op.mnemonic == "halt"):
            return False
        if ins.raw[:1] == b"\xff" or (len(ins.raw) == 1 and ins.raw[0] in _SELF_LOADS):
            return False
        if strict:
            if seen == 0 and _ODD_START.match(ins.op.text):
                return False
            if seen < 10 and _ODD.match(ins.op.text):
                odd += 1
                if odd >= 2:
                    return False
        if ins.flow in ("ret", "jump", "stop"):
            return True
        v += ins.size
        if not lay.valid(v) or split_vram(v)[1] & (BANK - 1) == 0:
            return False
    return False


def _mapper_write(ins: z80.Insn, st: State) -> tuple[int, object] | None:
    t = ins.op.text if ins.op else ""
    if t == "ld (nn),a" and ins.values.get("nn") in (0xFFFE, 0xFFFF):
        return ins.values["nn"], st.a
    if t in ("ld (hl),a", "ld (hl),n") and st.hl in (0xFFFE, 0xFFFF):
        return st.hl, (st.a if t.endswith("a") else ins.values["n"])
    return None


def _bank_mask(size: int) -> int:
    """The mapper only looks at as many bank bits as the ROM needs (`ld a,$82 / ld ($FFFF),a` maps bank 2 of a
    512 KiB game)."""
    banks = 1
    while banks * BANK < size:
        banks <<= 1
    return banks - 1


def _slot_value(val, mask: int):
    """What a slot holds after a mapper write of `val` (from A or an immediate)."""
    if isinstance(val, int):
        return val & mask
    if _ram(val):
        return ("var", val[1])
    return None


def _step(ins: z80.Insn, st: State, found: Found, mask: int) -> None:
    t = ins.op.text
    w = _mapper_write(ins, st)
    if w is not None:
        reg, val = w
        if _ram(val):
            found.bank_vars[val[1]] = 1 if reg == 0xFFFE else 2
        if reg == 0xFFFE:
            st.s1 = _slot_value(val, mask)
        else:
            st.s2 = _slot_value(val, mask)
    if t == "ld (nn),a" and isinstance(st.a, int) and ins.values["nn"] >= 0xC000:
        found.ram_consts.setdefault(ins.values["nn"], set()).add(st.a)
    elif t == "ld (hl),n" and isinstance(st.hl, int) and st.hl >= 0xC000:
        found.ram_consts.setdefault(st.hl, set()).add(ins.values["n"])
    elif t == "ld (hl),a" and isinstance(st.hl, int) and st.hl >= 0xC000 and isinstance(st.a, int):
        found.ram_consts.setdefault(st.hl, set()).add(st.a)
    if t == "ld a,n":
        st.a = ins.values["n"]
    elif t == "xor a":
        st.a = 0
    elif t == "ld a,(nn)":
        st.a = ("ram", ins.values["nn"])
    elif _WRITES_A.match(t):
        st.a = None
    if t == "ld hl,nn":
        st.hl = ins.values["nn"]
    elif t == "inc hl" and isinstance(st.hl, int):
        st.hl = (st.hl + 1) & 0xFFFF
    elif t == "dec hl" and isinstance(st.hl, int):
        st.hl = (st.hl - 1) & 0xFFFF
    elif _WRITES_HL.match(t):
        st.hl = None


def banks_at(rom: bytes, lay: Layout, found: Found, target: int, s1, s2, here: int) -> list[int]:
    """The banks a code address seen from `here` (vram) can be in: one when it's known; when the slot holds a
    bank variable, those of the constants the game stores in it that put plausible code there (all of them at
    the start of a slot, where games put each module's entry; otherwise only when just one does)."""
    here_bank, here_addr = split_vram(here)
    if target >= 0xC000:
        return []
    if target < 0x4000:
        return [0]
    if here_addr >= 0x4000 and (here_addr >> 14) == (target >> 14):
        return [here_bank]  # in the slot the code runs from: its own bank
    if not lay.mapper:
        return [target >> 14]
    slot = s1 if target < 0x8000 else s2
    if isinstance(slot, int):
        return [slot]
    if isinstance(slot, tuple) and slot[0] == "var":
        mask = _bank_mask(lay.size)
        cands = sorted({c & mask for c in found.ram_consts.get(slot[1], ())} - {0})
        ok = [b for b in cands if lay.valid(vram(b, target)) and
              plausible_code(rom, lay, vram(b, target), strict=True)]
        if target & (BANK - 1) == 0 or len(ok) == 1:
            return ok
    return []


def follow(rom: bytes, seeds: dict[int, str], extra_tables: bool = True, rounds: int = 8,
           names: dict[int, str] | None = None) -> Found:
    """Find the functions reachable from `seeds` (vram -> why), with tables and functions that don't return."""
    lay = layout(rom)
    found = Found(names=dict(names or {}))
    more: dict[int, tuple[str, tuple]] = {}
    before = None
    for _ in range(rounds):
        # each round starts again from the entry points, with what the last one learned (functions that don't
        # return, bank switchers and variables, tables, far jumps), so code wrongly followed before is dropped
        found.starts, found.mapping = {}, {}
        _trace_all(rom, lay, found, {**more, **{v: (why, (1, 2)) for v, why in seeds.items()}})
        bodies = _bodies(found)
        found.inline = {s for s, body in bodies.items() if body and _takes_return_address(found, body)}
        found.noreturn = _find_noreturn(found, bodies)
        more = {v: ("jump", m) for v, m in _far_jumps(found, bodies).items()}
        if extra_tables:
            more.update({v: ("table", m) for v, m in _tables(rom, lay, found).items() if v not in more})
        now = (frozenset(found.starts), frozenset(found.noreturn), frozenset(found.switchers), frozenset(more),
               frozenset((k, frozenset(v)) for k, v in found.ram_consts.items() if k in found.bank_vars),
               frozenset((k, frozenset(v)) for k, v in found.entered.items()))
        if now == before:
            break
        before = now
    return found


def _far_jumps(found: Found, bodies: dict[int, list[int]]) -> dict[int, tuple]:
    """Jump targets outside the jumping function's own bytes (its start up to the next function in the bank): code
    there belongs to no function unless it starts one. -> {target: the banks mapped at the jump}"""
    starts = sorted(found.starts)
    nxt = {s: (starts[k + 1] if k + 1 < len(starts) else s + BANK) for k, s in enumerate(starts)}
    out: dict[int, tuple] = {}
    for s, body in bodies.items():
        end = min(nxt[s], vram(split_vram(s)[0], (split_vram(s)[1] & ~(BANK - 1)) + BANK))
        for v in body:
            if not s <= v < end:
                continue
            for kind, t in found.refs.get(v, []):
                # also when it's a function already: next round starts over, and it must be seeded again
                if kind == 11 and not s <= t < end:
                    out.setdefault(t, found.state_at.get(v, (1, 2)))
    return out


def _trace_all(rom: bytes, lay: Layout, found: Found, pending: dict[int, tuple[str, tuple]]) -> None:
    """Follow the code from each entry point (vram -> (why, banks in slots 1 and 2 when it runs))."""
    found.refs.clear()
    found.insns.clear()
    found.state_at.clear()
    before, found.entered = found.entered, {}
    queue = [(v, why, mapping) for v, (why, mapping) in sorted(pending.items())]
    for v, _, mapping in queue:
        found.entered.setdefault(v, set()).add(mapping)
    seen: set[int] = set()
    while queue:
        v, why, mapping = queue.pop()
        if v in seen or not plausible_entry(rom, lay, v):
            continue
        seen.add(v)
        # a slot's bank holds inside a function only when everything that enters it (as the last round saw) agrees:
        # a helper called with the graphics bank in slot 2 and with the sound bank doesn't know which it has
        s1, s2 = _agreed(before.get(v, set()) | {mapping})
        found.starts.setdefault(v, why)
        found.mapping.setdefault(v, (s1, s2))
        for callee, m in _trace(rom, lay, found, v, State(s1, s2, ARG)):
            found.entered.setdefault(callee, set()).add(m)
            if callee not in seen:
                queue.append((callee, "call", m))


def _agreed(mappings: set) -> tuple:
    s1 = {m[0] for m in mappings}
    s2 = {m[1] for m in mappings}
    return (s1.pop() if len(s1) == 1 else None), (s2.pop() if len(s2) == 1 else None)


def plausible_entry(rom: bytes, lay: Layout, v: int) -> bool:
    """Where code can start: an instruction, and not the $FF filler of an empty bank (`rst $38` over and over)."""
    if not lay.valid(v):
        return False
    ins = _decode(rom, lay, v)
    if ins is None or ins.op is None:
        return False
    off = rom_offset(v)
    return rom[off:off + 2] != b"\xff\xff"


def _trace(rom: bytes, lay: Layout, found: Found, entry: int, st: State) -> list[tuple[int, tuple]]:
    """Follow one function from its entry; returns the functions it calls or jumps to, with the banks mapped."""
    bank = split_vram(entry)[0]
    mask = _bank_mask(lay.size)
    out: list[tuple[int, tuple]] = []
    work = [(entry, st)]
    visited: set[int] = set()
    while work:
        v, st = work.pop()
        while v not in visited:
            ins = _decode(rom, lay, v)
            if ins is None or ins.op is None:
                break
            visited.add(v)
            found.insns.setdefault(v, ins)
            found.state_at.setdefault(v, (st.s1, st.s2))
            addr = split_vram(v)[1]
            w = _mapper_write(ins, st)
            if w is not None and st.a == ARG:
                found.switchers.setdefault(entry, 1 if w[0] == 0xFFFE else 2)
            refs = []
            tgt = ins.target
            if tgt is not None:
                for tb in banks_at(rom, lay, found, tgt, st.s1, st.s2, v):
                    tv = vram(tb, tgt)
                    refs.append((10 if ins.flow == "call" else 11, tv))
                    if ins.flow == "call" or tb != bank or (tgt >> 14) != (addr >> 14) or tv in found.starts:
                        out.append((tv, (st.s1, st.s2)))
                    elif ins.flow in ("jump", "branch"):
                        work.append((tv, st.copy()))
            if "nn" in ins.values and ins.flow not in ("jump", "branch", "call"):
                val = ins.values["nn"]
                if "(nn)" in ins.op.text:  # memory it reads or writes (`ld hl,$C000` may be a VDP command)
                    dbanks = [0] if val >= 0xC000 else banks_at(rom, lay, found, val, st.s1, st.s2, v)
                    if dbanks:
                        dv = vram(0 if val >= 0xC000 else dbanks[0], val)
                        refs.append((2, dv))
                        if val < 0xFFFC:
                            size = 2 if re.search(r"(hl|bc|de|sp|ix|iy),\(nn\)|\(nn\),(hl|bc|de|sp|ix|iy)",
                                                  ins.op.text) else 1
                            found.data[dv] = max(found.data.get(dv, 0), size)
                elif ins.op.text.split(",")[0] in ("ld hl", "ld de", "ld bc", "ld ix", "ld iy") and \
                        0x0100 <= val < 0xC000:
                    for tb in banks_at(rom, lay, found, val, st.s1, st.s2, v)[:1]:
                        refs.append((3, vram(tb, val)))  # a pointer into the ROM: maybe a table
            if refs:
                found.refs[v] = refs
            # what happens next
            flow = ins.flow
            if flow == "call":
                callees = [t for k, t in refs if k == 10]
                if callees and all(c in found.noreturn for c in callees):
                    break
                slot = next((found.switchers[c] for c in callees if c in found.switchers), None)
                a_before = st.a
                st.a, st.hl = None, None
                if slot is not None:
                    if _ram(a_before):
                        found.bank_vars[a_before[1]] = slot
                    if slot == 1:
                        st.s1 = _slot_value(a_before, mask)
                    else:
                        st.s2 = _slot_value(a_before, mask)
            else:
                _step(ins, st, found, mask)
            if flow in ("ret", "jump", "stop"):
                break
            if ((addr + ins.size) >> 14) != (addr >> 14):
                break  # ran off the end of the bank
            v = vram(bank, addr + ins.size)
    return out


def _bodies(found: Found) -> dict[int, list[int]]:
    """Each function's instructions: its own flow over what was decoded, not into other functions."""
    by_fn: dict[int, list[int]] = {}
    for s in sorted(found.starts):
        body, work = [], [s]
        seen: set[int] = set()
        while work:
            v = work.pop()
            while v in found.insns and v not in seen:
                seen.add(v)
                ins = found.insns[v]
                body.append(v)
                for k, t in found.refs.get(v, []):
                    if k == 11 and t not in found.starts:
                        work.append(t)
                if ins.flow in ("ret", "jump", "stop"):
                    break
                if ins.flow == "call":
                    callees = [t for k, t in found.refs.get(v, []) if k == 10]
                    if callees and all(c in found.noreturn for c in callees):
                        break
                v = vram(split_vram(v)[0], split_vram(v)[1] + ins.size)
                if v in found.starts:
                    break  # ran into the next function
        by_fn[s] = body
    return by_fn


def _takes_return_address(found: Found, body: list[int]) -> bool:
    """A dispatcher that reads the bytes after its call: it pops (or swaps out) its return address before pushing
    anything, and ends in a computed jump. `rst $28 / .dw a, b, c` style tables follow each call to one."""
    if not any(found.insns[v].flow == "stop" for v in body):
        return False
    for v in sorted(body)[:12]:
        t = found.insns[v].op.text
        if t.startswith("push"):
            return False
        if t in ("pop hl", "pop de", "pop bc", "pop ix", "pop iy", "ex (sp),hl", "ex (sp),ix", "ex (sp),iy"):
            return True
    return False


def _find_noreturn(found: Found, by_fn: dict[int, list[int]]) -> set[int]:
    """Functions with no way back, so their callers' next bytes aren't code: no ret anywhere they reach, and they
    end in a loop to themselves, a jump to one of these, or they're dispatchers that take their return address
    (the bytes after the call are a table, see _takes_return_address). A computed jump alone (`jp (hl)`) proves
    nothing: the routine it jumps to returns to the caller. Neither does flow that just stopped."""
    noreturn: set[int] = {s for s, body in by_fn.items() if body and _takes_return_address(found, body)}
    changed = True
    while changed:
        changed = False
        for s, body in by_fn.items():
            if s in noreturn or not body:
                continue
            returns, ends = False, False
            for v in body:
                ins = found.insns[v]
                if ins.flow == "ret" or (ins.flow == "branch" and ins.op.mnemonic == "ret"):
                    returns = True
                    break
                ts = [t for k, t in found.refs.get(v, []) if k in (10, 11)]
                if ins.flow == "jump":  # a tail call returns if the function it jumps to does
                    if not ts or any(t in found.starts and t not in noreturn for t in ts):
                        returns = True
                        break
                    ends = ends or all(t in noreturn or t == v for t in ts)
                elif ins.flow == "call" and ts and all(t in noreturn for t in ts):
                    ends = True
            if not returns and ends:
                noreturn.add(s)
                changed = True
    return noreturn


def _tables(rom: bytes, lay: Layout, found: Found) -> dict[int, tuple]:
    """Code addresses in tables that code points at (`ld hl,table`, or the bytes after a call to a dispatcher that
    takes its return address): words that land on plausible code, read until one can't be a code address. A word
    into a slot whose bank isn't known is passed over (it still looks like an address). -> {entry: the banks
    mapped where the table is used}"""
    code_bytes = set()
    for v, ins in found.insns.items():
        code_bytes.update(range(v, v + ins.size))
    out: dict[int, tuple] = {}
    dispatchers = _dispatchers(found)
    for v, refs in found.refs.items():
        s1, s2 = found.state_at.get(v, (1, 2))
        for kind, t in refs:
            inline = kind == 10 and t in found.inline
            if inline:  # `call dispatcher / .dw a, b, c`: the table follows the call
                kind, t = 3, v + found.insns[v].size
            if kind != 3 or t in found.starts or (t in code_bytes and not inline):
                continue
            dispatched = inline or _dispatches_soon(found, v, dispatchers)
            entries, words = [], 0
            at = t
            for _ in range(64):
                if (at in code_bytes and not inline) or not lay.valid(at) or not lay.valid(at + 1):
                    break
                off = rom_offset(at)
                w = rom[off] | rom[off + 1] << 8
                if w >= 0xC000 or w < 0x0008:
                    break
                tbanks = banks_at(rom, lay, found, w, s1, s2, at)
                good = [vram(b, w) for b in tbanks if plausible_code(rom, lay, vram(b, w), strict=True)
                        and not (vram(b, w) in code_bytes and vram(b, w) not in found.starts)]
                if tbanks and not good:
                    break
                entries += good
                words += 1
                at += 2
            # a table the code is seen to jump through needs two entries; one that's only pointed at (its use may
            # be deeper than this can follow) needs four, it and they all in bank 0: data pointers that merely look
            # like code addresses rarely manage that
            plain = t >> 16 == 0 and all(e >> 16 == 0 for e in entries)
            enough = (len(entries) >= 2 or (entries and words >= 3)) if dispatched else (len(entries) >= 4 and plain)
            if enough and not _records(entries):
                for e in entries:
                    out.setdefault(e, (s1, s2))
    return out


def _dispatchers(found: Found) -> set[int]:
    """Functions that jump through a register within their first instructions (`jp (hl)`): jump-table helpers."""
    out = set()
    for s in found.starts:
        v = s
        for _ in range(16):
            ins = found.insns.get(v)
            if ins is None:
                break
            if ins.flow == "stop":
                out.add(s)
                break
            if ins.flow in ("ret", "jump"):
                break
            v = vram(split_vram(v)[0], split_vram(v)[1] + ins.size)
    return out


def _dispatches_soon(found: Found, v: int, dispatchers: set[int], within: int = 12) -> bool:
    """Whether the code after `v` (a `ld hl,table`) soon jumps through a register or calls a dispatcher, on its
    straight path (past calls, which return, and the not-taken side of conditional branches)."""
    for _ in range(within):
        ins = found.insns.get(v)
        if ins is None:
            return False
        if ins.flow == "stop":
            return True
        if ins.flow in ("call", "jump") and any(t in dispatchers for k, t in found.refs.get(v, []) if k in (10, 11)):
            return True
        if ins.flow in ("ret", "jump"):
            return False
        v = vram(split_vram(v)[0], split_vram(v)[1] + ins.size)
    return False


def _records(entries: list[int]) -> bool:
    """Addresses evenly spaced a few bytes apart point at records of a table, not at routines."""
    if len(entries) < 3:
        return False
    gaps = {b - a for a, b in zip(entries, entries[1:])}
    return len(gaps) == 1 and 0 < abs(gaps.pop()) < 16


# --------------------------------------------------------------------------------------- functions and data

@dataclass
class SmsFunction:
    name: str
    vram: int
    rom: int  # offset in the ROM file
    code: bytes
    refs: list[tuple[int, int, int]]  # (offset, kind, vram): 10 call, 11 jump, 2 data, 3 pointer
    insns: list[int]  # offsets of instructions (the rest of the bytes are data inside the function)
    noreturn: bool = False

    @property
    def n_insns(self) -> int:
        return max(1, len(self.insns))


def code_map(code: bytes, addr: int, noreturn_calls: set[int] | None = None) -> list[int]:
    """Offsets of the instructions in a function's bytes, following its own flow from the start (branches inside
    it, past calls). What isn't reached is data the function keeps inside it (tables, text)."""
    insns: set[int] = set()
    work = [0]
    while work:
        at = work.pop()
        while 0 <= at < len(code) and at not in insns:
            ins = z80.decode(code, at, (addr + at) & 0xFFFF)
            if ins.op is None or at + ins.size > len(code):
                break
            insns.add(at)
            t = ins.target
            if t is not None and ins.flow in ("jump", "branch"):
                rel = (t - addr) & 0xFFFF
                if 0 <= rel < len(code):
                    work.append(rel)
            if ins.flow in ("ret", "jump", "stop"):
                break
            if ins.flow == "call" and noreturn_calls and at in noreturn_calls:
                break
            at += ins.size
    return sorted(insns)


def functions(rom: bytes, found: Found) -> list[SmsFunction]:
    """Each found function's bytes: from its start to the end of the last instruction its own flow reaches before
    the next function starts."""
    lay = layout(rom)
    starts = sorted(v for v in found.starts if lay.valid(v))
    out = []
    for k, s in enumerate(starts):
        bank, addr = split_vram(s)
        slot_end = (addr & ~(BANK - 1)) + BANK
        nxt = starts[k + 1] if k + 1 < len(starts) else None
        same = nxt is not None and split_vram(nxt)[0] == bank and split_vram(nxt)[1] < slot_end
        limit = (split_vram(nxt)[1] if same else slot_end) - addr
        off = rom_offset(s)
        window = rom[off:off + max(0, limit)]
        nr = {i for i in range(len(window)) if any(k2 == 10 and t in found.noreturn
                                                    for k2, t in found.refs.get(s + i, []))}
        insns = code_map(window, addr, nr)
        if not insns:
            continue
        last = max(insns)
        end = last + z80.decode(window, last, (addr + last) & 0xFFFF).size
        code = window[:end]
        refs = [(i, kind, t) for i in insns for kind, t in found.refs.get(s + i, [])]
        name = found.names.get(s) or f"func_{s:08X}"
        out.append(SmsFunction(name, s, off, code, refs, insns, s in found.noreturn))
    return out


def simple_refs(code: bytes, v: int, insns: list[int], lay: Layout) -> list[tuple[int, int, int]]:
    """References of a function found after the import (an agent's split): calls and jumps whose bank is plain
    (bank 0, its own slot) and the RAM it uses. Banks mapped by the code itself aren't followed here."""
    bank, addr = split_vram(v)
    out = []
    for off in insns:
        ins = z80.decode(code, off, (addr + off) & 0xFFFF)
        t = ins.target
        if t is not None:
            tb = 0 if t < 0x4000 else bank if (t >> 14) == (addr >> 14) and addr >= 0x4000 else \
                (t >> 14) if not lay.mapper and t < 0xC000 else None
            if tb is not None:
                out.append((off, 10 if ins.flow == "call" else 11, vram(tb, t)))
        if ins.op is not None and "(nn)" in ins.op.text and ins.values.get("nn", 0) >= 0xC000:
            out.append((off, 2, vram(0, ins.values["nn"])))
    return out


def seeds(rom: bytes) -> dict[int, str]:
    """Where the code starts: reset, the interrupt (IM 1 jumps to 0x38) and the pause button's NMI (0x66)."""
    out = {0: "reset"}
    for at, why in ((0x38, "interrupt"), (0x66, "pause (NMI)")):
        if len(rom) > at and rom[at] not in (0xFF, 0x00):
            out[at] = why
    return out


_SYM = re.compile(r"^\s*([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{4})\s+([A-Za-z_.@$][\w.@$]*)\s*$")


def read_sym(text: str) -> dict[int, str]:
    """Labels of a WLA-DX style symbol file ([labels] section: `bank:address name`), as vram -> name. Local labels
    (`_loop`, `@x`, `.x`, `-`/`+`) are skipped; so is anything in a section other than [labels]."""
    out: dict[int, str] = {}
    section = "labels"
    for line in text.splitlines():
        line = line.split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").lower()
            continue
        if section != "labels":
            continue
        m = _SYM.match(line)
        if not m:
            continue
        bank, addr, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
        if name.startswith((".", "@", "_")) or not re.match(r"^[A-Za-z_]\w*$", name):
            continue
        out[vram(0 if addr >= 0xC000 else bank, addr)] = name
    return out


def _gap_starts(rom: bytes, lay: Layout, fns: list[SmsFunction], found: Found) -> list[int]:
    """Plausible function starts right after the end of a function, where no function starts yet and nothing
    points as data (a table right after its function reads like code too)."""
    starts = {f.vram for f in fns}
    pointed = {t for refs in found.refs.values() for k, t in refs if k in (2, 3)}
    ends = sorted({f.vram + len(f.code) for f in fns})
    out = []
    for v in ends:
        if v in starts or v in pointed or not lay.valid(v) or split_vram(v)[1] & (BANK - 1) == 0:
            continue
        if any(f.vram < v < f.vram + len(f.code) for f in fns):
            continue
        if plausible_code(rom, lay, v, strict=True):
            out.append(v)
    return out


@dataclass
class Split:
    functions: list[SmsFunction]
    data: dict[int, int]  # vram -> size: RAM variables and ROM data the code reads
    names: dict[int, str]  # vram -> name from a .sym file (functions and data)
    noreturn: list[int]
    switchers: dict[int, int]
    covered: int  # bytes of the ROM in functions


def split(rom: bytes, sym: dict[int, str] | None = None, log=print) -> Split:
    lay = layout(rom)
    start = seeds(rom)
    sym = sym or {}
    for v, name in sym.items():
        bank, addr = split_vram(v)
        if addr < 0xC000 and lay.valid(v) and plausible_code(rom, lay, v):
            start.setdefault(v, f"symbol {name}")
    found = follow(rom, start, names=sym)
    fns = functions(rom, found)
    # code nothing points at (called through tables this can't follow): what starts right where a function ends,
    # in a bank that has code, and reads like a function, is the next one. Repeated while it finds more.
    for _ in range(8):
        gaps = _gap_starts(rom, lay, fns, found)
        if not gaps:
            break
        start.update({v: "after a function" for v in gaps})
        found = follow(rom, start, names=sym)
        fns = functions(rom, found)
    covered = sum(len(f.code) for f in fns)
    log(f"found {len(fns)} functions ({covered * 100 // max(1, len(rom))}% of the ROM is code they reach); "
        f"{len(found.noreturn)} never return, {len(found.switchers)} switch banks")
    return Split(fns, found.data, sym, sorted(found.noreturn), found.switchers, covered)


# ----------------------------------------------------------------------------------------------- listings

def listing(fn_name: str, v: int, code: bytes, refs: list, name_of, insns: list[int] | None = None,
            header: bool = True) -> str:
    """Assembly for a function that assembles back to its bytes: labels for its own branch targets, the
    project's names for everything else (`name_of(vram)` -> name or None), `.db` for data inside it."""
    bank, addr = split_vram(v)
    insns = code_map(code, addr) if insns is None else insns
    at_insn = set(insns)
    ref_at: dict[int, list] = {}
    for off, kind, t in refs:
        ref_at.setdefault(off, []).append((kind, t))
    # what the listing prints as instructions: walking forward, an instruction that starts inside the previous one
    # (code that jumps into the middle of an instruction) can't be shown, and is reached as `name+$offset`
    printed, off = set(), 0
    while off < len(code):
        if off in at_insn:
            printed.add(off)
            off += z80.decode(code, off, (addr + off) & 0xFFFF).size
        else:
            off += 1
    # local labels: branch targets inside the function
    local = set()
    for off in printed:
        ins = z80.decode(code, off, (addr + off) & 0xFFFF)
        t = ins.target
        if t is not None and ins.flow in ("jump", "branch"):
            rel = (t - addr) & 0xFFFF
            if 0 < rel < len(code) and rel in printed:
                local.add(rel)
    out = []
    if header:
        slot = addr >> 14
        out.append(f"; {fn_name}: bank {bank} (${bank:02X}), runs at ${addr:04X} (slot {slot}), "
                   f"ROM offset ${rom_offset(v):05X}, {len(code)} bytes")
    out.append(f"{fn_name}:")
    off = 0
    pending_data = bytearray()
    data_start = 0

    def flush():
        nonlocal pending_data
        for k in range(0, len(pending_data), 8):
            chunk = pending_data[k:k + 8]
            out.append("    .db " + ", ".join(f"${b:02X}" for b in chunk) + f"  ; ${(addr + data_start + k) & 0xFFFF:04X}")
        pending_data = bytearray()

    while off < len(code):
        if off not in printed:
            if not pending_data:
                data_start = off
            pending_data.append(code[off])
            off += 1
            continue
        flush()
        if off in local:
            out.append(f".L{(addr + off) & 0xFFFF:04X}:")
        ins = z80.decode(code, off, (addr + off) & 0xFFFF)
        here = ref_at.get(off, [])

        def name(value, kind, here=here, off=off):
            rel = (value - addr) & 0xFFFF
            if kind == "code" and 0 < rel < len(code) and rel in local:
                return f".L{value:04X}"
            if kind == "code" and rel == 0:
                return fn_name
            if kind == "code" and 0 < rel < len(code):
                return f"{fn_name}+${rel:X}"  # into an instruction, or into bytes shown as data
            for k, t in here:
                if (t & 0xFFFF) == value:
                    n = name_of(t)
                    if n:
                        return n
            if value >= 0xC000 or kind == "data":
                n = name_of(vram(0, value)) if value >= 0xC000 else None
                if n:
                    return n
            return None

        out.append(f"    {ins.text(name)}")
        off += ins.size
    flush()
    return "\n".join(out) + "\n"
