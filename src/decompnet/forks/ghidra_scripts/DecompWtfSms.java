// decomp.wtf: Ghidra's reading of a Master System game, for agents to understand its Z80 code.
// The program is the ROM's first 48 KiB (banks 0-2 at 0x0000-0xBFFF, as a game starts). This script adds an overlay
// for every other bank at the slot its functions run from, RAM, the project's names, and the functions (from the
// project, so Ghidra's own guesses don't matter), then writes one JSON object per line: {"vram": n, "c": "..."}.
// args: <rom> <entries file: "f|d bank addr size name" per line, hex> <output>
// Each function gets exactly the bytes decomp.wtf found for it, so Ghidra doesn't wander into data or RAM.
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DecompWtfSms extends GhidraScript {
    private final Map<String, AddressSpace> overlays = new HashMap<>();
    private byte[] rom;

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    /** Where bank `bank` running at `addr` is in this program: the main space for banks 0-2 at their own slots. */
    private Address place(int bank, int addr) throws Exception {
        int slot = addr >> 14;
        if (addr >= 0xC000 || (bank == slot && bank <= 2)) return toAddr(addr);
        String name = String.format("bank%02d_%x", bank, slot * 0x4000);
        AddressSpace sp = overlays.get(name);
        if (sp == null) {
            int base = slot * 0x4000;
            int len = Math.min(0x4000, rom.length - bank * 0x4000);
            if (len <= 0) return null;
            MemoryBlock blk = currentProgram.getMemory().createInitializedBlock(name, toAddr(base),
                    new ByteArrayInputStream(rom, bank * 0x4000, len), len, monitor, true);
            blk.setExecute(true);
            sp = blk.getStart().getAddressSpace();
            overlays.put(name, sp);
        }
        return sp.getAddress(addr);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        rom = Files.readAllBytes(Path.of(args[0]));
        var mem = currentProgram.getMemory();
        if (mem.getBlock(toAddr(0xC000)) == null) {
            mem.createUninitializedBlock("ram", toAddr(0xC000), 0x4000, false).setWrite(true);
        }
        List<Object[]> fns = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] p = line.trim().split("\\s+");
            if (p.length < 5) continue;
            int bank = Integer.parseInt(p[1], 16), addr = Integer.parseInt(p[2], 16);
            int size = Integer.parseInt(p[3], 16);
            Address a = place(bank, addr);
            if (a == null) continue;
            try {
                createLabel(a, p[4], true, SourceType.USER_DEFINED);
            } catch (Exception e) {
                // a name Ghidra won't take: keep its own
            }
            if (p[0].equals("f") && size > 0) fns.add(new Object[] {a, (bank << 16) | addr, size, p[4]});
        }
        for (Object[] f : fns) {
            Address a = (Address) f[0];
            AddressSet body = new AddressSet(a, a.add((Integer) f[2] - 1));
            new DisassembleCommand(a, body, true).applyTo(currentProgram, monitor);
        }
        for (Object[] f : fns) {
            Address a = (Address) f[0];
            if (getFunctionAt(a) != null) continue;
            AddressSetView body = new AddressSet(a, a.add((Integer) f[2] - 1));
            try {
                currentProgram.getFunctionManager().createFunction((String) f[3], a, body, SourceType.USER_DEFINED);
            } catch (Exception e) {
                // overlapping another function's bytes: Ghidra's own idea of the body will do
                createFunction(a, null);
            }
        }
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[2]), StandardCharsets.UTF_8))) {
            for (Object[] f : fns) {
                if (monitor.isCancelled()) break;
                Function fn = getFunctionAt((Address) f[0]);
                if (fn == null) continue;
                DecompileResults r = ifc.decompileFunction(fn, 20, monitor);
                if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
                w.println("{\"vram\": " + f[1] + ", \"c\": " + quote(r.getDecompiledFunction().getC()) + "}");
            }
        } finally {
            ifc.dispose();
        }
    }
}
