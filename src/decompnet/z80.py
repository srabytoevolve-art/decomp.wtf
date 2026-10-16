"""Z80: one opcode table behind both the disassembler and the assembler, so the two always agree.

The table is generated the way the Z80 decodes (x/y/z/p/q fields of the opcode byte, then the CB, ED, DD/FD and
DDCB/FDCB pages), including the undocumented instructions games use (ixh/ixl, sll, `in f,(c)`...). An instruction
that has a second encoding (`ld hl,(nn)` is 2A and ED 6B) keeps its plain name for the first and gets the opcode as
a suffix for the other (`ld.ed6b hl,(nn)`), so every byte sequence disassembles to text that assembles back to the
same bytes.

Syntax: Zilog, as in WLA-DX, sjasmplus and most SMS disassemblies (`ld a,(ix+5)`, `jr nz,.loop`, `$1F`/`0x1F`/`1Fh`),
and what SDCC writes (`ld a,#5`, `ld a,5 (ix)`, `00102$:` labels, `.area`/`.globl`), so C compiled by SDCC goes
through the same assembler as hand-written code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

R = ["b", "c", "d", "e", "h", "l", "(hl)", "a"]
RP = ["bc", "de", "hl", "sp"]
RP2 = ["bc", "de", "hl", "af"]
CC = ["nz", "z", "nc", "c", "po", "pe", "p", "m"]
ALU = ["add a,", "adc a,", "sub ", "sbc a,", "and ", "xor ", "or ", "cp "]
ROT = ["rlc", "rrc", "rl", "rr", "sla", "sra", "sll", "srl"]
IM = ["0", "0", "1", "2", "0", "0", "1", "2"]
BLOCK = [["ldi", "cpi", "ini", "outi"], ["ldd", "cpd", "ind", "outd"], ["ldir", "cpir", "inir", "otir"],
         ["lddr", "cpdr", "indr", "otdr"]]

REGISTERS = {"a", "b", "c", "d", "e", "h", "l", "f", "i", "r", "af", "af'", "bc", "de", "hl", "sp", "ix", "iy",
             "ixh", "ixl", "iyh", "iyl", "(hl)", "(bc)", "(de)", "(sp)", "(c)", "(ix)", "(iy)"}
CONDITIONS = set(CC)
# instructions whose number operand is part of the opcode (bit 3,a / im 1 / rst $38)
LITERAL_FIRST = {"bit", "set", "res", "im", "rst"}


@dataclass(frozen=True)
class Op:
    text: str  # template: n (8-bit), nn (16-bit), d (index displacement), rel (relative branch)
    enc: tuple  # bytes and the fields "n", "nn", "d", "rel" in the order they're stored
    flow: str = ""  # "": runs on; "jump"/"branch"/"call"/"ret"/"stop" (for following code)

    @property
    def size(self) -> int:
        return sum(2 if x == "nn" else 1 for x in self.enc)

    @property
    def mnemonic(self) -> str:
        return self.text.split(" ", 1)[0]


def _flow(text: str) -> str:
    m = text.split(" ", 1)[0].split(".", 1)[0]
    ops = text.split(" ", 1)[1] if " " in text else ""
    if m in ("jp", "jr"):
        if ops in ("(hl)", "(ix)", "(iy)"):
            return "stop"  # a computed jump: where it goes isn't in the code
        return "branch" if "," in ops else "jump"
    if m == "djnz":
        return "branch"
    if m == "call":
        return "call"
    if m == "ret":
        return "branch" if ops else "ret"
    if m in ("reti", "retn"):
        return "ret"
    if m == "rst":
        return "call"
    return ""


def _main_page() -> list[tuple[int, str]]:
    out = []
    for op in range(256):
        x, y, z, p, q = op >> 6, (op >> 3) & 7, op & 7, (op >> 4) & 3, (op >> 3) & 1
        t = None
        if x == 0:
            if z == 0:
                t = ["nop", "ex af,af'", "djnz rel", "jr rel"][y] if y < 4 else f"jr {CC[y - 4]},rel"
            elif z == 1:
                t = f"ld {RP[p]},nn" if q == 0 else f"add hl,{RP[p]}"
            elif z == 2:
                t = (["ld (bc),a", "ld (de),a", "ld (nn),hl", "ld (nn),a"] if q == 0 else
                     ["ld a,(bc)", "ld a,(de)", "ld hl,(nn)", "ld a,(nn)"])[p]
            elif z == 3:
                t = f"{'inc' if q == 0 else 'dec'} {RP[p]}"
            elif z == 4:
                t = f"inc {R[y]}"
            elif z == 5:
                t = f"dec {R[y]}"
            elif z == 6:
                t = f"ld {R[y]},n"
            else:
                t = ["rlca", "rrca", "rla", "rra", "daa", "cpl", "scf", "ccf"][y]
        elif x == 1:
            t = "halt" if (z == 6 and y == 6) else f"ld {R[y]},{R[z]}"
        elif x == 2:
            t = f"{ALU[y]}{R[z]}"
        else:
            if z == 0:
                t = f"ret {CC[y]}"
            elif z == 1:
                t = f"pop {RP2[p]}" if q == 0 else ["ret", "exx", "jp (hl)", "ld sp,hl"][p]
            elif z == 2:
                t = f"jp {CC[y]},nn"
            elif z == 3:
                t = ["jp nn", None, "out (n),a", "in a,(n)", "ex (sp),hl", "ex de,hl", "di", "ei"][y]
            elif z == 4:
                t = f"call {CC[y]},nn"
            elif z == 5:
                t = f"push {RP2[p]}" if q == 0 else ["call nn", None, None, None][p]
            elif z == 6:
                t = f"{ALU[y]}n"
            else:
                t = f"rst 0x{y * 8:02x}"
        if t is not None:
            out.append((op, t))
    return out


def _cb_page() -> list[tuple[int, str]]:
    out = []
    for op in range(256):
        x, y, z = op >> 6, (op >> 3) & 7, op & 7
        out.append((op, f"{ROT[y]} {R[z]}" if x == 0 else f"{['bit', 'res', 'set'][x - 1]} {y},{R[z]}"))
    return out


def _ed_page() -> list[tuple[int, str]]:
    out = []
    for op in range(256):
        x, y, z, p, q = op >> 6, (op >> 3) & 7, op & 7, (op >> 4) & 3, (op >> 3) & 1
        t = None
        if x == 1:
            if z == 0:
                t = "in f,(c)" if y == 6 else f"in {R[y]},(c)"
            elif z == 1:
                t = "out (c),0" if y == 6 else f"out (c),{R[y]}"
            elif z == 2:
                t = f"{'sbc' if q == 0 else 'adc'} hl,{RP[p]}"
            elif z == 3:
                t = f"ld (nn),{RP[p]}" if q == 0 else f"ld {RP[p]},(nn)"
            elif z == 4:
                t = "neg"
            elif z == 5:
                t = "reti" if y == 1 else "retn"
            elif z == 6:
                t = f"im {IM[y]}"
            else:
                t = ["ld i,a", "ld r,a", "ld a,i", "ld a,r", "rrd", "rld", None, None][y]
        elif x == 2 and z <= 3 and y >= 4:
            t = BLOCK[y - 4][z]
        if t is not None:
            out.append((op, t))
    return out


def _index(text: str, xy: str) -> str | None:
    """An unprefixed instruction as DD (ix) or FD (iy) makes it, or None when the prefix changes nothing."""
    if text in ("ex de,hl", "exx") or text.startswith(("ex de", "exx")):
        return None
    if text == "jp (hl)":
        return f"jp ({xy})"
    mnem, _, ops = text.partition(" ")
    args = ops.split(",") if ops else []
    if "(hl)" in args:  # (hl) becomes (ix+d); h and l in the same instruction stay h and l
        return f"{mnem} " + ",".join(f"({xy}+d)" if a == "(hl)" else a for a in args)
    new = [xy if a == "hl" else f"{xy}h" if a == "h" else f"{xy}l" if a == "l" else
           f"({xy})" if a == "(hl)" else a for a in args]
    if new == args:
        return None
    if mnem == "ex" and args == ["(sp)", "hl"]:
        return f"ex (sp),{xy}"
    return f"{mnem} " + ",".join(new)


def _encoding(prefix: tuple, op: int, text: str) -> tuple:
    fields = []
    for tok in re.findall(r"\(\w+\+d\)|\bnn\b|\bn\b|\brel\b", text.split(" ", 1)[1] if " " in text else ""):
        fields.append("d" if tok.endswith("+d)") else tok)
    return (*prefix, op, *fields)


def _build() -> list[Op]:
    ops: list[Op] = []
    for op, t in _main_page():
        ops.append(Op(t, _encoding((), op, t)))
    for op, t in _cb_page():
        ops.append(Op(t, (0xCB, op)))
    for op, t in _ed_page():
        ops.append(Op(t, _encoding((0xED,), op, t)))
    for pre, xy in ((0xDD, "ix"), (0xFD, "iy")):
        for op, t in _main_page():
            it = _index(t, xy)
            if it is None or op == 0xCB:
                continue
            ops.append(Op(it, _encoding((pre,), op, it)))
        # DDCB d op: the displacement comes before the opcode. The documented form (z = 6) first, so the
        # undocumented copies of bit (z != 6) are the ones that get a suffix
        for op in sorted(range(256), key=lambda o: (o >> 3, (o & 7) != 6, o & 7)):
            x, y, z = op >> 6, (op >> 3) & 7, op & 7
            base = f"{ROT[y]} ({xy}+d)" if x == 0 else f"{['bit', 'res', 'set'][x - 1]} {y},({xy}+d)"
            if z != 6 and x != 1:
                base += f",{R[z]}"  # undocumented: the result is also copied to a register
            ops.append(Op(base, (pre, 0xCB, "d", op)))
    # second encodings of the same instruction get the opcode as a suffix (`neg.ed4c`)
    seen: set[str] = set()
    out = []
    for o in ops:
        text = o.text
        if text in seen:
            fixed = "".join(f"{b:02x}" for b in o.enc if isinstance(b, int))
            mnem, _, rest = text.partition(" ")
            text = f"{mnem}.{fixed}" + (f" {rest}" if rest else "")
        seen.add(text)
        out.append(Op(text, o.enc, _flow(text)))
    return out


OPS: list[Op] = _build()


def _decode_index() -> dict:
    """{prefix bytes: {opcode: Op}}; DDCB/FDCB keyed by (pre, 0xCB) with the opcode after the displacement."""
    idx: dict[tuple, dict[int, Op]] = {}
    for o in OPS:
        if len(o.enc) >= 4 and o.enc[1] == 0xCB and o.enc[2] == "d":
            idx.setdefault((o.enc[0], 0xCB), {})[o.enc[3]] = o
            continue
        k = 0
        while k < len(o.enc) and isinstance(o.enc[k], int):
            k += 1
        pre, opcode = tuple(o.enc[:k - 1]), o.enc[k - 1]
        idx.setdefault(pre, {})[opcode] = o
    return idx


_DECODE = _decode_index()


# ------------------------------------------------------------------------------------------------- disassembly

@dataclass
class Insn:
    addr: int  # where it runs (the CPU address)
    size: int
    op: Op | None  # None: not an instruction (shown as a byte)
    values: dict = field(default_factory=dict)  # n, nn, d, rel (the target address)
    raw: bytes = b""

    @property
    def flow(self) -> str:
        return self.op.flow if self.op else "stop"

    @property
    def target(self) -> int | None:
        """Where a jump, branch or call goes (None for computed ones and everything else)."""
        if self.op is None or self.op.flow not in ("jump", "branch", "call"):
            return None
        if "rel" in self.values:
            return self.values["rel"]
        if "nn" in self.values:
            return self.values["nn"]
        if self.op.mnemonic == "rst":
            return int(self.op.text.split()[1], 16)
        return None

    def text(self, name=None) -> str:
        """Assembly for this instruction. `name(addr, kind)` may give a symbol for an address: kind is "code" for
        jump/call targets and "data" for (nn) operands; return None to keep the number."""
        if self.op is None:
            return f".db ${self.raw[0]:02X}"
        mnem, _, ops = self.op.text.partition(" ")
        code = self.op.flow in ("jump", "branch", "call")

        def field(m):
            tok = m.group(0)
            if tok == "+d)":
                d = self.values["d"]
                return f"{'+' if d >= 0 else '-'}${abs(d):02X})"
            if tok == "n":
                return f"${self.values['n']:02X}"
            kind = "code" if code else "data" if "(nn)" in ops else "imm"
            return _addr(self.values[tok], kind, name)

        ops = re.sub(r"\b(?:nn|n|rel)\b|\+d\)", field, ops)
        return f"{mnem} {ops.replace(',', ', ')}" if ops else mnem


def _addr(value: int, kind: str, name) -> str:
    if name is not None:
        s = name(value, kind)
        if s:
            return s
    return f"${value:04X}"


def decode(data: bytes, at: int = 0, addr: int | None = None) -> Insn:
    """The instruction at data[at] (running at CPU address `addr`). A byte that starts no instruction (an unused
    prefix, a page hole, or the end of the data) comes back with op None, size 1."""
    addr = at if addr is None else addr
    page, k = (), at
    if k < len(data) and data[k] in (0xDD, 0xFD) and k + 1 < len(data) and data[k + 1] == 0xCB:
        if k + 3 < len(data):
            o = _DECODE[(data[k], 0xCB)][data[k + 3]]
            d = data[k + 2] - 256 if data[k + 2] & 0x80 else data[k + 2]
            return Insn(addr, 4, o, {"d": d}, bytes(data[k:k + 4]))
        return Insn(addr, 1, None, {}, bytes(data[at:at + 1]))
    while k < len(data) and data[k] in (0xCB, 0xED, 0xDD, 0xFD) and not page:
        page = (data[k],)
        k += 1
    table = _DECODE.get(page, {})
    if k >= len(data) or data[k] not in table:
        return Insn(addr, 1, None, {}, bytes(data[at:at + 1]))
    o = table[data[k]]
    if at + o.size > len(data):
        return Insn(addr, 1, None, {}, bytes(data[at:at + 1]))
    vals, j = {}, k + 1
    for f in o.enc[len(page) + 1:]:
        if f == "nn":
            vals["nn"] = data[j] | data[j + 1] << 8
            j += 2
        elif f == "n":
            vals["n"] = data[j]
            j += 1
        elif f == "d":
            vals["d"] = data[j] - 256 if data[j] & 0x80 else data[j]
            j += 1
        elif f == "rel":
            rel = data[j] - 256 if data[j] & 0x80 else data[j]
            vals["rel"] = (addr + o.size + rel) & 0xFFFF
            j += 1
    return Insn(addr, o.size, o, vals, bytes(data[at:at + o.size]))


def disassemble(data: bytes, addr: int = 0) -> list[Insn]:
    out, at = [], 0
    while at < len(data):
        ins = decode(data, at, (addr + at) & 0xFFFF)
        out.append(ins)
        at += ins.size
    return out


# --------------------------------------------------------------------------------------------------- assembly

class AsmError(ValueError):
    def __init__(self, line: int, msg: str):
        super().__init__(f"line {line}: {msg}" if line else msg)
        self.line = line


def _shape(arg: str) -> tuple[str, str | None]:
    """(shape, expression) of one operand: a register or condition stays itself, a number becomes X, (X) or
    (ix+X)."""
    a = arg.strip()
    low = a.lower().replace(" ", "")
    if low in REGISTERS or low in CONDITIONS:
        return low, None
    m = re.match(r"^(.+?)\s*\(\s*(ix|iy)\s*\)$", a, re.I)  # SDCC: 5 (ix)
    if m and not m.group(1).strip().endswith(("+", "-")) and _balanced(m.group(1)):
        return f"({m.group(2).lower()}+X)", m.group(1).strip()
    m = re.match(r"^\(\s*(ix|iy)\s*([+-].*)\)$", a, re.I)
    if m:
        expr = m.group(2).strip()
        return f"({m.group(1).lower()}+X)", expr[1:] if expr.startswith("+") else f"0{expr}"
    if a.startswith("(") and a.endswith(")") and _balanced(a[1:-1]):
        return "(X)", a[1:-1].strip()
    return "X", a


def _balanced(s: str) -> bool:
    depth = 0
    for ch in s:
        depth += ch == "("
        depth -= ch == ")"
        if depth < 0:
            return False
    return depth == 0


def _template_key(o: Op) -> tuple:
    mnem, _, ops = o.text.partition(" ")
    shapes = []
    for a in (ops.split(",") if ops else []):
        a = re.sub(r"\((ix|iy)\+d\)", r"(\1+X)", a)
        a = re.sub(r"^\((nn|n)\)$", "(X)", a)
        a = re.sub(r"^(nn|n|rel)$", "X", a)
        shapes.append(a)
    return mnem, tuple(shapes)


_ENCODE: dict[tuple, Op] = {}
for _o in OPS:
    _ENCODE.setdefault(_template_key(_o), _o)
_MNEMONICS = {k[0] for k in _ENCODE}


@dataclass
class Field:
    """A number in the output the assembler couldn't know on the first pass, or one that names an address."""
    offset: int
    kind: str  # n | nn | d | rel
    expr: str
    line: int
    insn_addr: int
    address: bool = False  # an absolute code/data address (call nn, jp nn, (nn))


@dataclass
class Assembled:
    code: bytes  # the bytes of the area
    org: int
    labels: dict[str, int]  # label -> CPU address
    insns: list[tuple[int, int, int]]  # (offset, size, line): instructions
    data: list[tuple[int, int, int]]  # (offset, size, line): bytes from .db/.dw/.ds
    bare: list[tuple[int, int, str, int]]  # (offset, line, text, value): addresses written as plain numbers
    globals: list[str]  # labels declared .globl (SDCC) or defined at the left margin with `::`
    symbols_used: set[str]


_NUM = re.compile(r"^(?:0x[0-9a-f]+|\$[0-9a-f]+|[0-9][0-9a-f]*h|%[01]+|0b[01]+|[0-9]+)$", re.I)
_TOKEN = re.compile(r"\s*(0x[0-9a-fA-F]+|\$[0-9a-fA-F]+|[0-9][0-9a-fA-F]*[hH]\b|%[01]+|0b[01]+|[0-9]+\$|[0-9]+"
                    r"|'(?:\\.|[^'])'|[A-Za-z_.@][\w.@$]*|<<|>>|[-+*/%&|^~()<>$])")


def _number(tok: str) -> int:
    t = tok.lower()
    if t.startswith("0x"):
        return int(t[2:], 16)
    if t.startswith("$"):
        return int(t[1:], 16)
    if t.endswith("h"):
        return int(t[:-1], 16)
    if t.startswith("%"):
        return int(t[1:], 2)
    if t.startswith("0b"):
        return int(t[2:], 2)
    return int(t, 10)


class _Expr:
    """Expressions: numbers, symbols, `$`/`.` (here), + - * / % & | ^ ~ << >> and SDCC's < (low byte) > (high)."""

    def __init__(self, text: str, resolve, here: int):
        self.toks = []
        pos = 0
        text = text.strip()
        while pos < len(text):
            m = _TOKEN.match(text, pos)
            if not m or m.end() == pos:
                raise ValueError(f"can't read `{text[pos:]}`")
            self.toks.append(m.group(1))
            pos = m.end()
            while pos < len(text) and text[pos].isspace():
                pos += 1
        self.k = 0
        self.resolve, self.here = resolve, here
        self.symbols: set[str] = set()

    def value(self) -> int:
        v = self._or()
        if self.k != len(self.toks):
            raise ValueError(f"unexpected `{self.toks[self.k]}`")
        return v

    def _peek(self):
        return self.toks[self.k] if self.k < len(self.toks) else None

    def _take(self):
        self.k += 1
        return self.toks[self.k - 1]

    def _bin(self, ops, nxt):
        v = nxt()
        while self._peek() in ops:
            o = self._take()
            w = nxt()
            v = {"|": lambda a, b: a | b, "^": lambda a, b: a ^ b, "&": lambda a, b: a & b,
                 "<<": lambda a, b: a << b, ">>": lambda a, b: a >> b, "+": lambda a, b: a + b,
                 "-": lambda a, b: a - b, "*": lambda a, b: a * b,
                 "/": lambda a, b: a // b if b else _div0(), "%": lambda a, b: a % b if b else _div0()}[o](v, w)
        return v

    def _or(self):
        return self._bin(("|",), self._xor)

    def _xor(self):
        return self._bin(("^",), self._and)

    def _and(self):
        return self._bin(("&",), self._shift)

    def _shift(self):
        return self._bin(("<<", ">>"), self._add)

    def _add(self):
        return self._bin(("+", "-"), self._mul)

    def _mul(self):
        return self._bin(("*", "/", "%"), self._unary)

    def _unary(self):
        t = self._peek()
        if t == "-":
            self._take()
            return -self._unary()
        if t == "+":
            self._take()
            return self._unary()
        if t == "~":
            self._take()
            return ~self._unary()
        if t == "<":  # SDCC: low byte
            self._take()
            return self._unary() & 0xFF
        if t == ">":  # SDCC: high byte
            self._take()
            return (self._unary() >> 8) & 0xFF
        return self._atom()

    def _atom(self):
        t = self._take() if self._peek() is not None else None
        if t is None:
            raise ValueError("expression ends too soon")
        if t == "(":
            v = self._or()
            if self._peek() != ")":
                raise ValueError("missing )")
            self._take()
            return v
        if t in ("$", "."):
            return self.here
        if t.startswith("'"):
            body = t[1:-1]
            return ord(body.encode().decode("unicode_escape") if body.startswith("\\") else body)
        if _NUM.match(t):
            return _number(t)
        if re.match(r"^[0-9]+\$$", t) or re.match(r"^[A-Za-z_.@]", t):
            self.symbols.add(t)
            v = self.resolve(t)
            if v is None:
                raise KeyError(t)
            return v
        raise ValueError(f"can't read `{t}`")


def _div0():
    raise ValueError("division by zero")


def _split_args(s: str) -> list[str]:
    out, depth, cur, quote = [], 0, "", None
    for ch in s:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
            continue
        if ch in "\"'" and not (ch == "'" and cur.strip().lower() == "af"):
            quote = ch
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _strip_comment(line: str) -> str:
    out, quote = "", None
    for i, ch in enumerate(line):
        if quote:
            out += ch
            if ch == quote and line[i - 1] != "\\":
                quote = None
            continue
        if ch == ";":
            break
        if ch == '"' or (ch == "'" and not out.lower().rstrip().endswith("af") and i + 2 < len(line) and line[i + 2] == "'"):
            quote = ch
        out += ch
    return out.rstrip()


_DIRECTIVES_DATA = {".db", "db", ".byte", "defb", ".dw", "dw", ".word", "defw", ".ds", "ds", "defs", ".blkb",
                    ".ascii", ".asc", ".str", ".asciz", ".strz"}
_DIRECTIVES_IGNORED = {".module", ".optsdcc", ".globl", ".global", ".area", ".even", ".odd", ".hd64", ".z80",
                       ".r800", ".ez80", ".local", ".endfunc", ".function"}
FORBIDDEN = {".org", "org", ".incbin", "incbin", ".include", "include", ".bank", ".section", ".macro", "macro",
             ".rept", "rept", ".fill", ".orga", ".rombanks", ".memorymap", ".if", ".ifdef", ".bndry", ".setdp"}


def assemble(source: str, org: int, resolve=lambda name: None, area: str = "_CODE", reach: bool = True) -> Assembled:
    """Assemble `source` so its first byte in `area` runs at `org`. `resolve(name)` gives the address of a symbol
    the source uses but doesn't define (other functions, RAM variables); None means it doesn't exist.

    Raises AsmError (with the line) for anything it can't assemble, and for directives that place code by hand
    (.org, .incbin...), which would let a "match" come from somewhere other than the code written. reach=False
    skips checking that relative branches reach (for a trial at another address, to find where labels fall)."""
    lines = source.splitlines()
    labels: dict[str, int] = {}
    equs: dict[str, int] = {}
    globals_: list[str] = []
    # pass 1 sizes everything (unknown labels count as 0); pass 2 fills in the numbers
    for final in (False, True):
        out = bytearray()
        insns, data, bare = [], [], []
        used: set[str] = set()
        cur_area = "_CODE"
        last_global = ""
        for n, raw in enumerate(lines, 1):
            line = _strip_comment(raw)
            if not line.strip():
                continue
            here = (org + len(out)) & 0xFFFF
            # labels: `name:`, `name::` (exported), `.local:`, `@local:`, `00102$:` (SDCC)
            while True:
                m = re.match(r"^\s*([A-Za-z_.@][\w.@$]*|[0-9]+\$)\s*(::?)", line)
                if not m or (m.group(2) == ":" and line[m.end():m.end() + 1] == "="):
                    break
                name = _qualify(m.group(1), last_global)
                if cur_area == area:
                    if not final and name in labels:
                        raise AsmError(n, f"label `{m.group(1)}` is defined twice")
                    labels[name] = here
                if not m.group(1).startswith((".", "@")) and not re.match(r"^[0-9]+\$$", m.group(1)):
                    last_global = m.group(1)
                if m.group(2) == "::" and m.group(1) not in globals_:
                    globals_.append(m.group(1))
                line = line[m.end():]
            if not line.strip():
                continue
            # equates: NAME = expr, NAME .equ expr, NAME equ expr, .equ NAME, expr
            m = re.match(r"^\s*([A-Za-z_][\w]*)\s*(?:=|\.?equ\b)\s*(.+)$", line, re.I) or \
                re.match(r"^\s*\.equ\s+([A-Za-z_]\w*)\s*,\s*(.+)$", line, re.I)
            if m:
                try:
                    equs[m.group(1)] = _eval(m.group(2), lambda s: _lookup(s, labels, equs, resolve, last_global,
                                                                          final), here, used)
                except KeyError as e:
                    if final:
                        raise AsmError(n, f"`{e.args[0]}` isn't defined") from None
                except ValueError as e:
                    raise AsmError(n, str(e)) from None
                continue
            word, _, rest = line.strip().partition(" ")
            if "\t" in word:
                word, _, more = word.partition("\t")
                rest = (more + " " + rest).strip()
            lw = word.lower()
            rest = rest.strip()
            if lw in FORBIDDEN:
                raise AsmError(n, f"`{word}` isn't allowed: write the function's code, the judge places it")
            if lw in (".globl", ".global"):
                for g in _split_args(rest):
                    if g not in globals_:
                        globals_.append(g)
                continue
            if lw == ".area":
                cur_area = rest.split("(")[0].strip()
                continue
            if lw in _DIRECTIVES_IGNORED:
                continue
            look = lambda s: _lookup(s, labels, equs, resolve, last_global, final)  # noqa: E731
            if lw in _DIRECTIVES_DATA:
                start = len(out)
                try:
                    out += _data(lw, rest, look, here, used)
                except KeyError as e:
                    raise AsmError(n, f"`{e.args[0]}` isn't defined") from None
                except ValueError as e:
                    raise AsmError(n, str(e)) from None
                if cur_area == area:
                    data.append((start, len(out) - start, n))
                else:
                    del out[start:]
                continue
            if lw.split(".")[0] not in _MNEMONICS and lw not in _MNEMONICS:
                raise AsmError(n, f"unknown instruction `{word}`")
            try:
                code, bare_value = _instruction(lw, rest, look, here, used, final and reach)
            except KeyError as e:
                raise AsmError(n, f"`{e.args[0]}` isn't defined (a function, variable or label of this project)") from None
            except ValueError as e:
                raise AsmError(n, str(e)) from None
            if cur_area != area:
                continue
            insns.append((len(out), len(code), n))
            if bare_value is not None:
                bare.append((len(out), n, raw.strip(), bare_value))
            out += code
    return Assembled(bytes(out), org, labels, insns, data, bare, globals_, used)


def _qualify(name: str, last_global: str) -> str:
    return f"{last_global}{name}" if name.startswith((".", "@")) and last_global else name


def _lookup(name: str, labels, equs, resolve, last_global: str, final: bool):
    full = _qualify(name, last_global)
    for key in (full, name):
        if key in labels:
            return labels[key]
        if key in equs:
            return equs[key]
    v = resolve(name)
    if v is None and name.startswith("_"):  # SDCC writes C names with a leading underscore
        v = resolve(name[1:])
    if v is None and not final:
        return 0
    return v


def _eval(expr: str, look, here: int, used: set[str] | None = None) -> int:
    e = _Expr(expr.replace("#", ""), look, here)
    v = e.value()
    if used is not None:
        used |= e.symbols
    return v


def _data(kind: str, rest: str, look, here: int, used) -> bytes:
    out = bytearray()
    args = _split_args(rest) if rest else []
    if kind in (".ds", "ds", "defs", ".blkb"):
        size = _eval(args[0], look, here, used)
        fill = _eval(args[1], look, here, used) & 0xFF if len(args) > 1 else 0
        if not 0 <= size <= 0x4000:
            raise ValueError(f"bad size {size}")
        return bytes([fill]) * size
    for a in args:
        if a.startswith('"') and a.endswith('"') and len(a) >= 2:
            if kind in (".dw", "dw", ".word", "defw"):
                raise ValueError("a string in .dw")
            out += a[1:-1].encode("latin-1").decode("unicode_escape").encode("latin-1")
            continue
        v = _eval(a, look, here + len(out), used)
        if kind in (".dw", "dw", ".word", "defw"):
            out += (v & 0xFFFF).to_bytes(2, "little")
        else:
            if not -128 <= v <= 255:
                raise ValueError(f"{a} = {v} doesn't fit in a byte")
            out.append(v & 0xFF)
    if kind in (".asciz", ".strz"):
        out.append(0)
    return bytes(out)


def _instruction(mnem: str, rest: str, look, here: int, used: set[str], final: bool) -> tuple[bytes, int | None]:
    args = _split_args(rest) if rest else []
    base = mnem.split(".")[0]
    if len(args) == 1 and base in ("add", "adc", "sbc"):
        args = ["a", *args]  # `add b` means `add a,b`
    if len(args) == 2 and base in ("sub", "and", "xor", "or", "cp") and args[0].lower().replace(" ", "") == "a":
        args = args[1:]  # `sub a,b` (some assemblers) means `sub b`
    shapes, exprs = [], []
    for k, a in enumerate(args):
        if k == 0 and mnem.split(".")[0] in LITERAL_FIRST:
            v = _eval(a, look, here, used)
            shapes.append(f"0x{v:02x}" if mnem.split(".")[0] == "rst" else str(v))
            exprs.append(None)
            continue
        if mnem.split(".")[0] in ("in", "out") and a.strip().lower().replace(" ", "") == "(c)":
            shapes.append("(c)")
            exprs.append(None)
            continue
        if mnem.split(".")[0] == "out" and k == 1 and a.strip() == "0":
            shapes.append("0")
            exprs.append(None)
            continue
        low = a.strip().lower().replace(" ", "")
        if low in ("(ix)", "(iy)") and base != "jp":
            s, e = f"{low[:-1]}+X)", "0"  # (ix) is (ix+0), except in jp (ix)
        else:
            s, e = _shape(a)
        shapes.append(s)
        exprs.append(e)
    key = (mnem, tuple(shapes))
    op = _ENCODE.get(key)
    if op is None and "(X)" in shapes:  # `ld a,(5+3)` is an immediate in some syntaxes: try it as one
        op = _ENCODE.get((mnem, tuple("X" if s == "(X)" else s for s in shapes)))
    if op is None:
        raise ValueError(f"no such instruction: {mnem} {rest}".strip())
    values = [_eval(e, look, here, used) if e is not None else None for e in exprs]
    vals = [v for v in values if v is not None]
    fields = [f for f in op.enc if not isinstance(f, int)]
    if len(fields) != len(vals):  # ld (ix+d),n: two fields; jp (ix): none
        vals = vals[:len(fields)]
    out = bytearray()
    vi = 0
    bare = None  # the address, when one is written as a plain number
    for f in op.enc:
        if isinstance(f, int):
            out.append(f)
            continue
        v = vals[vi]
        e = [x for x in exprs if x is not None][vi]
        vi += 1
        if f == "nn":
            if not -0x8000 <= v <= 0xFFFF:
                raise ValueError(f"{e} = {v} doesn't fit in 16 bits")
            out += (v & 0xFFFF).to_bytes(2, "little")
            if op.flow in ("jump", "branch", "call") or "(nn)" in op.text:
                if not _has_symbol(e):
                    bare = v & 0xFFFF
        elif f == "n":
            if not -128 <= v <= 255:
                raise ValueError(f"{e} = {v} doesn't fit in a byte")
            out.append(v & 0xFF)
        elif f == "d":
            if not -128 <= v <= 127:
                raise ValueError(f"index offset {v} is out of range (-128..127)")
            out.append(v & 0xFF)
        elif f == "rel":
            rel = v - (here + op.size)
            if not -128 <= rel <= 127:
                if final:
                    raise ValueError(f"{op.mnemonic} target is {rel} bytes away (it reaches -128..127): use jp")
                rel = 0
            out.append(rel & 0xFF)
            if not _has_symbol(e) and e.strip() not in ("$", ".") and not re.match(r"^[0-9]+\$$", e.strip()):
                bare = v & 0xFFFF
    return bytes(out), bare


def _has_symbol(expr: str) -> bool:
    return bool(re.search(r"(?<![0-9$%])\b[A-Za-z_.@][\w.@$]*", re.sub(r"0x[0-9a-fA-F]+|\$[0-9a-fA-F]+|"
                                                                      r"\b[0-9][0-9a-fA-F]*[hH]\b|0b[01]+", "", expr)))
