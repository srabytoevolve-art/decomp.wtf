"""Master System from scratch: a homemade 64 KiB game, assembled here, split by following its code (banks mapped by
number, by a RAM variable and through a jump table), then judged byte for byte: the listing matches, `.db` bytes
for code and numbers where names exist don't, renames keep matches, an agent's split adds what wasn't found, and
the export rebuilds the ROM. With SDCC installed, C is compiled, assembled and judged the same way.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from decompnet import z80
from decompnet.app.engine import RomNetwork
from decompnet.rom import detect, sdcc, sms

BANK = 0x4000

# (bank, address it runs at, source): bank 0 at 0x0000, the sound driver in bank 2 at 0x8000, a module in bank 3
# mapped into slot 1 by the number the game keeps in wModule
PIECES = [
    (0, 0x0000, """
Reset:                     ; 6 bytes: rst $08 starts at $0008
    di
    im 1
    jp Start
"""),
    (0, 0x0008, """
SetVdpAddress:
    ld a, e
    out ($BF), a
    ld a, d
    out ($BF), a
    ret
"""),
    (0, 0x0020, """
JumpTable:
    add a, a
    ld e, a
    ld d, 0
    add hl, de
    ld a, (hl)
    inc hl
    ld h, (hl)
    ld l, a
    jp (hl)
"""),
    (0, 0x0038, """
IrqVector:
    jp Irq
"""),
    (0, 0x0066, """
Pause:
    retn
"""),
    (0, 0x0100, """
Start:
    ld sp, $DFF0
    ld a, $82              ; bank 2 (the mapper ignores the high bit on a 64 KiB game)
    ld ($FFFF), a
    call SoundInit
    xor a
    ld (wState), a
    ld a, 1
    ld (wModule), a
    ld de, $4000
    rst $08
    ei
MainLoop:
    ld a, (wModule)
    ld ($FFFE), a
    ld a, (wState)
    ld hl, StateTable
    rst $20
    jp MainLoop
StateTable:
    .dw StateTitle, StatePlay
StateTitle:
    ld a, 1
    ld (wState), a
    ld a, 3
    ld (wModule), a
    ret
StatePlay:
    call ModuleEntry
    ld hl, Records
    ld a, (hl)
    ld (wScore), a
    ret
Irq:
    push af
    in a, ($BF)
    ld a, ($FFFF)
    push af
    ld a, 2
    ld ($FFFF), a
    call SoundUpdate
    pop af
    ld ($FFFF), a
    pop af
    ei
    reti
Records:                   ; a table of 4-byte records: data, not code
    .db $02, $02, $01, $C9, $02, $02, $01, $C9, $02, $02, $01, $C9, $02, $02, $01, $C9
"""),
    (0, 0x0300, """
Orphan:                    ; nothing calls it: only a symbol file (or an agent) can say it's a function
    ld hl, wScore
    inc (hl)
    jr nz, .done
    inc hl
    inc (hl)
.done:
    ret
"""),
    (2, 0x8000, """
SoundInit:
    ld b, 4
    ld a, $9F
.loop:
    out ($7F), a
    add a, $20
    djnz .loop
    ret
SoundUpdate:
    ld a, (wSoundTimer)
    inc a
    ld (wSoundTimer), a
    and $07
    ret nz
    jp SoundInit
"""),
    (3, 0x4000, """
ModuleEntry:
    call ModuleHelper
    ld hl, wScore
    inc (hl)
    ret
ModuleHelper:
    ld a, (wState)
    cp 1
    jr z, .one
    xor a
.one:
    ld (wState), a
    ret
"""),
]
RAM = {"wState": 0xC000, "wModule": 0xC001, "wScore": 0xC002, "wSoundTimer": 0xC010}
SYM = "[labels]\n00:0300 Orphan\n00:c002 wScore\n"


def build_rom(pieces=PIECES, size=4 * BANK) -> tuple[bytes, dict]:
    """Assemble the pieces where they go: (ROM, label -> vram)."""
    labels: dict[str, int] = {}
    for final in (False, True):
        rom = bytearray(b"\xff" * size)
        look = {**{k: v for k, v in RAM.items()}, **{k: v & 0xFFFF for k, v in labels.items()}}
        for bank, addr, src in pieces:
            res = z80.assemble(src, addr, (lambda n: look.get(n)) if final else (lambda n: look.get(n, 0)),
                               reach=final)
            for name, at in res.labels.items():
                if "." not in name:
                    labels[name] = sms.vram(bank, at)
            off = bank * BANK + (addr & (BANK - 1))
            rom[off:off + len(res.code)] = res.code
    rom[0x7FF0:0x8000] = b"TMR SEGA\xff\xff\x00\x00\x34\x12\x00\x4e"
    return bytes(rom), labels


@pytest.fixture(scope="module")
def game(tmp_path_factory):
    work = tmp_path_factory.mktemp("sms")
    rom, labels = build_rom()
    path = work / "Demo Quest.sms"
    path.write_bytes(rom)
    return path, rom, labels


def test_every_opcode_disassembles_to_text_that_assembles_back():
    for op in z80.OPS:
        buf = bytes(0x12 if f == "n" else 0xFE if f == "d" else 0x05 if f == "rel" else f
                    for f in op.enc if f != "nn") if "nn" not in op.enc else None
        if buf is None:
            buf = b"".join(bytes([f]) if isinstance(f, int) else b"\x34\x12" if f == "nn" else
                           b"\x12" if f == "n" else b"\xfe" if f == "d" else b"\x05" for f in op.enc)
        ins = z80.decode(buf, 0, 0x8000)
        assert ins.size == len(buf), op.text
        assert z80.assemble(ins.text(), 0x8000).code == buf, (op.text, ins.text())


@pytest.mark.parametrize("src,hexed", [
    ("ld a,#5", "3e05"), ("ld a, 5 (ix)", "dd7e05"), ("ld a,-2 (iy)", "fd7efe"), ("ld a,(ix)", "dd7e00"),
    ("jp (ix)", "dde9"), ("sub a,b", "90"), ("ld hl,($C000)", "2a00c0"), ("out ($BE),a", "d3be"),
    ("ex af,af'", "08"), ("rst $38", "ff"), ("im 1", "ed56"), ("bit 7,(ix+3)", "ddcb037e"),
    ("ld (ix+4),$12", "dd360412"), ("neg.ed4c", "ed4c"), ("ld.ed6b hl,($1234)", "ed6b3412"), ("djnz $", "10fe"),
    ("ld hl,<0x1234", "213400"), ("ld hl,>0x1234", "211200"), ("ld a,'A'", "3e41"), ("ld bc,%1010", "010a00"),
])
def test_syntax(src, hexed):
    assert z80.assemble(src, 0).code.hex() == hexed


def test_the_assembler_refuses_placing_code_by_hand():
    with pytest.raises(z80.AsmError, match="isn't allowed"):
        z80.assemble(".org $100\nret", 0)
    with pytest.raises(z80.AsmError, match="use jp"):
        z80.assemble("jr far\n.ds 200\nfar: ret", 0)


def test_detect(game):
    path, rom, _ = game
    picked = detect.identify(path)
    assert picked.platform == "sms" and picked.info["title"] == "Demo Quest"
    assert picked.info["mapper"] == "sega" and picked.info["game_code"] == "1234"
    assert picked.info["compiler_guess"] == "Z80 assembly"


def test_the_code_is_followed_through_banks_tables_and_variables(game):
    _, rom, labels = game
    res = sms.split(rom, log=lambda *_: None)
    found = {f.vram for f in res.functions}
    want = {labels[n] for n in ("Reset", "SetVdpAddress", "JumpTable", "IrqVector", "Pause", "Start", "StateTitle",
                                "StatePlay", "Irq", "SoundInit", "SoundUpdate", "ModuleEntry", "ModuleHelper")}
    assert want <= found  # bank 2 by number ($82), bank 3 through wModule, the states through StateTable
    assert labels["Orphan"] not in found  # nothing reaches it
    records = labels["Records"]
    assert not any(records <= v < records + 16 for v in found)  # a table of records isn't code
    assert labels["MainLoop"] not in found  # Start runs into its loop: one function
    assert sms.vram(0, RAM["wModule"]) in res.data and sms.vram(0, RAM["wState"]) in res.data


def test_a_symbol_file_names_and_seeds(game):
    _, rom, labels = game
    res = sms.split(rom, sms.read_sym(SYM), log=lambda *_: None)
    orphan = next(f for f in res.functions if f.vram == labels["Orphan"])
    assert orphan.name == "Orphan" and len(orphan.code) == 9


@pytest.fixture(scope="module")
def project(game, tmp_path_factory):
    path, _, _ = game
    work = tmp_path_factory.mktemp("sms-app")
    net = RomNetwork(work / "app.db", work / "ws")
    slug = net.import_rom(path, confirmed=True, log=lambda *_: None)
    return net, slug


def test_import(project):
    net, slug = project
    ov = net.overview(slug)
    assert ov["platform"] == "sms" and ov["compiler"]["toolchain"] == "z80asm" and ov["compiler"]["installed"]
    assert ov["exportable"] and ov["functions"] >= 13


def _name_at(net, slug, vram):
    return net.store.one("SELECT name FROM functions WHERE vram=?", vram)["name"]


def test_the_listing_matches_and_shortcuts_dont(project, game):
    net, slug = project
    _, _, labels = game
    agent, _ = net.local_agent("sms-agent")
    proj = net._project(slug)
    name = _name_at(net, slug, labels["StateTitle"])
    net.claim(agent, slug, name, "easiest")
    fn = net._function(name, slug)
    listing = net._asm_text(fn, proj)
    assert "ld (D_0000C000), a" in listing  # RAM it writes has a name

    cheat = f"{name}:\n" + "".join(f"    .db ${b:02X}\n" for b in fn["target"])
    text = net.compile_and_diff(agent, name, cheat, slug)
    assert not text.startswith("✅") and ".db/.dw over bytes the game runs as code" in text

    bare = listing.replace("(D_0000C000)", "($C000)")
    text = net.compile_and_diff(agent, name, bare, slug)
    assert not text.startswith("✅") and "write `D_0000C000`" in text

    text = net.compile_and_diff(agent, name, "; title screen state\n" + listing.replace(".L", ".l"), slug)
    assert text.startswith("✅ MATCH")


def test_renames_reach_matched_code(project, game):
    net, slug = project
    agent, _ = net.local_agent("sms-agent")
    assert net.rename_symbol(agent, slug, "D_0000C000", "wState", "the game state").startswith("✅")
    _, _, labels = game
    name = _name_at(net, slug, labels["StateTitle"])
    src = net._function(name, slug)["matched_source"]
    assert "(wState)" in src and "D_0000C000" not in src


def test_rename_over_a_hidden_second_name(project):
    """Two names at one address in the database: the table shows the last, the first only blocks its name."""
    net, slug = project
    agent, _ = net.local_agent("sms-agent")
    pid = net._project(slug)["id"]
    with net.store.tx() as db:
        for name in ("ghost_a", "visible_b"):
            db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(?,?,?,?,?)",
                       (pid, name, 0xC1F0, 1, "data"))
    net._syms.pop(pid, None)
    assert net.rename_symbol(agent, slug, "visible_b", "ghost_a").startswith("✅")
    rows = net.store.all("SELECT name FROM symbols WHERE project_id=? AND address=?", pid, 0xC1F0)
    assert [r["name"] for r in rows] == ["ghost_a"]


def test_an_agent_adds_a_function_the_finder_missed(project, game):
    net, slug = project
    _, _, labels = game
    agent, _ = net.local_agent("sms-agent")
    prev = net.store.one("SELECT name FROM functions WHERE vram<? ORDER BY vram DESC LIMIT 1", labels["Orphan"])["name"]
    text = net.split_function(agent, slug, prev, f"0x{labels['Orphan']:08X}", "AddScore")
    assert text.startswith("✅ new function AddScore"), text
    fn = net._function("AddScore", slug)
    assert fn["size"] == 9
    listing = net._asm_text(fn, net._project(slug))
    net.claim(agent, slug, "AddScore", "easiest")
    assert net.compile_and_diff(agent, "AddScore", listing, slug).startswith("✅ MATCH")


def test_cross_bank_calls_resolve(project, game):
    net, slug = project
    _, _, labels = game
    fn = net._function(_name_at(net, slug, labels["Irq"]), slug)
    listing = net._asm_text(fn, net._project(slug))
    assert f"call {_name_at(net, slug, labels['SoundUpdate'])}" in listing  # bank 2, mapped with ld a,2


def test_export_rebuilds_the_rom(project):
    net, slug = project
    res = net.export_rom(slug, log=lambda *_: None)
    assert res["identical"], res["log"]
    assert res["matched"] >= 2
    out = Path(res["path"])
    assert (out / "tools" / "z80.py").exists() and (out / "src").is_dir()
    proc = subprocess.run([sys.executable, "build.py"], cwd=out, capture_output=True, text=True)
    assert "identical" in proc.stdout


C_FUNCTION = """
extern unsigned char wScore;
extern void PlaySound(unsigned char id);
static const unsigned char table[4] = {1, 2, 4, 8};
unsigned char add_points(unsigned char n) {
    unsigned char i;
    for (i = 0; i < n; i++)
        wScore += table[i & 3];
    if (wScore > 100)
        PlaySound(3);
    return wScore;
}
"""


@pytest.mark.skipif(sdcc.find() is None, reason="needs SDCC")
def test_sdcc_c_matches_like_assembly(tmp_path):
    """Homebrew: C compiled by SDCC is placed in a game, then decompiled from it: the same C matches."""
    import os

    exe = sdcc.find()
    env = dict(os.environ, PATH=str(exe.parent) + os.pathsep + os.environ.get("PATH", ""))
    (tmp_path / "f.c").write_text(C_FUNCTION)
    subprocess.run([str(exe), "-mz80", "-S", "--no-std-crt0", "f.c", "-o", "f.s"], cwd=tmp_path, env=env, check=True)
    asm = (tmp_path / "f.s").read_text()
    pieces = PIECES + [(0, 0x0400, asm), (0, 0x0500, "_PlaySound:\n    ret\n")]
    pieces = [(b, a, s.replace("StatePlay:\n    call ModuleEntry", "StatePlay:\n    ld a, 5\n    call _add_points\n"
                                                                         "    call ModuleEntry")) for b, a, s in pieces]
    RAM["_wScore"] = RAM["wScore"]
    try:
        rom, labels = build_rom(pieces)
    finally:
        del RAM["_wScore"]
    path = tmp_path / "homebrew.sms"
    path.write_bytes(rom)
    (tmp_path / "homebrew.sym").write_text("[labels]\n00:0500 PlaySound\n00:c002 wScore\n")
    net = RomNetwork(tmp_path / "app.db", tmp_path / "ws")
    slug = net.import_rom(path, toolchain="sdcc", confirmed=True, log=lambda *_: None)
    name = _name_at(net, slug, labels["_add_points"])
    assert net.rename_symbol(net.local_agent("x")[0], slug, name, "add_points").startswith("✅")
    agent, _ = net.local_agent("c-agent")
    net.claim(agent, slug, "add_points", "easiest")
    assert net.compile_and_diff(agent, "add_points", C_FUNCTION, slug).startswith("✅ MATCH")
    wrong = C_FUNCTION.replace("table[i & 3]", "table[i & 1]")
    assert not net.compile_and_diff(agent, "add_points", wrong, slug).startswith("✅")


def test_ghidra_reads_the_banks(game, tmp_path):
    """Ghidra's C for agents: functions in every bank, under the project's names (skipped without Ghidra)."""
    from decompnet.forks import ghidra

    if not ghidra.available():
        pytest.skip("needs Ghidra and Java 21")
    path, rom, labels = game
    res = sms.split(rom, log=lambda *_: None)
    entries = [("f", f.vram >> 16, f.vram & 0xFFFF, len(f.code), f.name) for f in res.functions]
    entries += [("d", 0, addr, 0, name) for name, addr in RAM.items()]
    c = ghidra.decompile_sms(path, entries, tmp_path / "c.json")
    assert labels["ModuleEntry"] in c and labels["SoundInit"] in c  # banks 3 and 2, in overlays
    assert "wScore" in c[labels["ModuleEntry"]]
