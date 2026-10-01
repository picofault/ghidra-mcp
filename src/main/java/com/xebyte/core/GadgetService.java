package com.xebyte.core;

import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service for exploit primitives: ROP/JOP/COOP gadget discovery.
 *
 * <p>Two scan engines share one record format:
 * <ul>
 *   <li>aligned (default): walks the existing listing backwards from each
 *       terminator instruction, so it only finds gadgets made of instructions
 *       Ghidra has already defined. Fast.</li>
 *   <li>byte scan ({@code include_unaligned=true}): forward-disassembles from
 *       every byte offset with {@link PseudoDisassembler}, which finds the
 *       classic unintended gadgets (jumping into the middle of an instruction,
 *       e.g. {@code pop rdi ; ret} inside {@code pop r15}). Much slower on
 *       large binaries — bound it with start/end.</li>
 * </ul>
 */
@McpToolGroup(value = "exploit", description = "ROP/JOP gadget search for exploit development")
public class GadgetService {

    private static final int MAX_INSTRUCTIONS_LIMIT = 20;
    private static final int MAX_RESULTS_LIMIT = 100000;

    private final ProgramProvider programProvider;

    public GadgetService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    /** One scanned instruction, source-agnostic (listing or pseudo). */
    private record ScannedInstr(Address address, String text, byte[] bytes, FlowType flowType,
                                Address fallThrough) {}

    @McpTool(path = "/find_rop_gadgets",
             description = "Search executable memory for ROP/JOP gadgets: short instruction sequences ending in a "
                         + "control-flow terminator. terminator=ret (default) finds sequences ending in a return "
                         + "(classic ROP); terminator=jmp finds sequences ending in an indirect jump like 'JMP RSP' "
                         + "(JOP / stack-pivot dispatch); terminator=call finds sequences ending in an indirect call "
                         + "(COOP); terminator=all reports every kind. Each gadget executes linearly: every "
                         + "instruction falls through to the next (mid-chain unconditional branches are rejected; "
                         + "conditional branches and calls may appear since they fall through). "
                         + "filter is a case-insensitive substring matched against the gadget text, e.g. "
                         + "\"pop rdi\" or \"pop rdi ; ret\". Addresses are the program's loaded addresses — directly "
                         + "usable in an exploit when the target has no ASLR / fixed load base (typical firmware). "
                         + "By default only instructions Ghidra has already defined are considered (fast). "
                         + "include_unaligned=true additionally disassembles at every byte offset, finding "
                         + "unintended gadgets (e.g. 'pop rdi ; ret' hiding inside 'pop r15') — much slower on "
                         + "large binaries, so bound it with start/end. Thumb/misaligned ARM support via "
                         + "include_unaligned is experimental: gadget addresses are raw byte offsets (set the "
                         + "T-bit, addr|1, when the target needs it). Results are capped at max_results "
                         + "(default 10000); when the cap is hit, truncated=true and total is a lower bound.",
             category = "exploit")
    public Response findGadgets(
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName,
            @Param(value = "terminator", defaultValue = "ret",
                   description = "Terminator kind: ret | jmp | call | all. ret = returns (ROP), jmp = indirect "
                               + "jumps (JOP), call = indirect calls (COOP).") String terminator,
            @Param(value = "max_instructions", defaultValue = "6",
                   description = "Maximum instructions per gadget, including the terminator (1-20, default 6). "
                               + "Shorter gadgets are always reported too.") int maxInstructions,
            @Param(value = "filter", defaultValue = "",
                   description = "Case-insensitive substring matched against the gadget's disassembly text "
                               + "(e.g. \"pop rdi\", \"xchg rax, rsp\"). Omit for all gadgets.") String filter,
            @Param(value = "start", paramType = "address", defaultValue = "",
                   description = "Optional range start. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Gadgets must start at or after this address.") String startStr,
            @Param(value = "end", paramType = "address", defaultValue = "",
                   description = "Optional range end (inclusive). Same address forms as start. Gadgets must end "
                               + "at or before this address.") String endStr,
            @Param(value = "include_unaligned", defaultValue = "false",
                   description = "true: also scan every byte offset with an on-the-fly disassembler to find "
                               + "unintended gadgets (slow on large binaries — bound with start/end). "
                               + "false (default): only defined instructions, fast.") boolean includeUnaligned,
            @Param(value = "max_results", defaultValue = "10000",
                   description = "Stop scanning after this many matching gadgets (1-100000, default 10000). "
                               + "truncated=true in the response means the cap was hit.") int maxResults,
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of gadgets to skip before this page starts; 0 begins at the first.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Maximum gadgets returned in this page (default 100). Pass 0 or a negative "
                               + "value for no limit; `total` in the response always reports the full count "
                               + "of gadgets found.") int limit) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        String term = terminator == null ? "ret" : terminator.trim().toLowerCase();
        if (!term.equals("ret") && !term.equals("jmp") && !term.equals("call") && !term.equals("all")) {
            return Response.err("terminator must be one of: ret | jmp | call | all (got '" + terminator + "')");
        }
        if (maxInstructions < 1 || maxInstructions > MAX_INSTRUCTIONS_LIMIT) {
            return Response.err("max_instructions must be between 1 and " + MAX_INSTRUCTIONS_LIMIT);
        }
        if (maxResults < 1 || maxResults > MAX_RESULTS_LIMIT) {
            return Response.err("max_results must be between 1 and " + MAX_RESULTS_LIMIT);
        }

        Address startAddr = null;
        Address endAddr = null;
        if (startStr != null && !startStr.isBlank()) {
            startAddr = ServiceUtils.parseAddress(program, startStr);
            if (startAddr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }
        }
        if (endStr != null && !endStr.isBlank()) {
            endAddr = ServiceUtils.parseAddress(program, endStr);
            if (endAddr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }
        }
        if (startAddr != null && endAddr != null && startAddr.compareTo(endAddr) > 0) {
            return Response.err("start (" + startStr + ") is after end (" + endStr + ")");
        }

        String filterLc = filter == null ? "" : filter.trim().toLowerCase();

        try {
            Memory memory = program.getMemory();
            Listing listing = program.getListing();
            AddressSet scanSet = buildScanSet(memory, startAddr, endAddr);
            if (scanSet.isEmpty()) {
                return Response.err("No executable, initialized memory in the requested range. "
                        + "Check the range against list_segments.");
            }

            List<Map<String, Object>> gadgets = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            boolean truncated = scanAligned(program, listing, scanSet, term, maxInstructions, filterLc,
                    maxResults, gadgets, seen);
            if (!truncated && includeUnaligned) {
                truncated = scanUnaligned(program, listing, memory, scanSet, startAddr, endAddr, term,
                        maxInstructions, filterLc, maxResults, gadgets, seen);
            }

            // Page over the collected matches, mirroring ServiceUtils.paged's
            // envelope with the extra scan fields appended.
            int start = Math.max(0, offset);
            int end = (limit > 0) ? Math.min(gadgets.size(), start + limit) : gadgets.size();
            List<Map<String, Object>> page = (start >= gadgets.size())
                    ? List.of() : gadgets.subList(start, end);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("gadgets", page);
            result.put("count", page.size());
            result.put("offset", start);
            if (limit > 0) {
                result.put("limit", limit);
            }
            result.put("total", gadgets.size());
            result.put("truncated", truncated);
            result.put("terminator", term);
            result.put("max_instructions", maxInstructions);
            result.put("filter", filterLc);
            result.put("include_unaligned", includeUnaligned);
            return Response.ok(result);
        } catch (Exception e) {
            Msg.error(this, "find_rop_gadgets failed", e);
            return Response.err("find_rop_gadgets failed: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Terminator classification
    // -----------------------------------------------------------------------

    /**
     * Classify an instruction's flow type as a gadget terminator.
     * Returns "ret", "jmp", "call", or null when the instruction is none of them.
     *
     * <p>Returns (x86 RET, ARM {@code bx lr} / {@code pop {pc}}) are TERMINATOR
     * family: {@code isTerminal()} without call/jump bits. JOP dispatchers are
     * computed jumps ({@code jmp rsp}, {@code jmp [rax]}). COOP dispatchers are
     * computed calls. Direct jumps/calls are deliberately excluded — a gadget
     * must transfer control through a register or memory the caller controls.
     */
    static String classifyTerminator(FlowType ft) {
        if (ft == null) {
            return null;
        }
        if (ft.isTerminal() && !ft.isCall() && !ft.isJump()) {
            return "ret";
        }
        if (ft.isJump() && ft.isComputed()) {
            return "jmp";
        }
        if (ft.isCall() && ft.isComputed()) {
            return "call";
        }
        return null;
    }

    private static boolean kindMatches(String term, String kind) {
        return "all".equals(term) || term.equals(kind);
    }

    // -----------------------------------------------------------------------
    // Scan range
    // -----------------------------------------------------------------------

    /** Executable + initialized block ranges, clipped to [start, end] when given. */
    private static AddressSet buildScanSet(Memory memory, Address startAddr, Address endAddr) {
        AddressSet set = new AddressSet();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) {
                continue;
            }
            Address bStart = block.getStart();
            Address bEnd = block.getEnd();
            if (startAddr != null && bEnd.compareTo(startAddr) < 0) {
                continue;
            }
            if (endAddr != null && bStart.compareTo(endAddr) > 0) {
                continue;
            }
            Address s = (startAddr != null && startAddr.compareTo(bStart) > 0) ? startAddr : bStart;
            Address e = (endAddr != null && endAddr.compareTo(bEnd) < 0) ? endAddr : bEnd;
            set.addRange(s, e);
        }
        return set;
    }

    // -----------------------------------------------------------------------
    // Aligned scan: backwards from each terminator in the listing
    // -----------------------------------------------------------------------

    private boolean scanAligned(Program program, Listing listing, AddressSet scanSet, String term,
                                int maxInstructions, String filterLc, int maxResults,
                                List<Map<String, Object>> out, Set<String> seen) {
        InstructionIterator it = listing.getInstructions(scanSet, true);
        while (it.hasNext()) {
            Instruction terminator = it.next();
            String kind = classifyTerminator(terminator.getFlowType());
            if (kind == null || !kindMatches(term, kind)) {
                continue;
            }

            // Walk backwards while each predecessor falls through to the next
            // instruction — that is what makes the chain execute linearly.
            // A predecessor without a fall-through (unconditional jump, ret,
            // terminator) breaks the chain by construction.
            Deque<ScannedInstr> chain = new ArrayDeque<>();
            chain.addFirst(toScanned(terminator));
            Address cur = terminator.getAddress();
            while (chain.size() < maxInstructions) {
                Instruction prev = listing.getInstructionBefore(cur);
                if (prev == null || !scanSet.contains(prev.getAddress())) {
                    break;
                }
                Address fall = prev.getFallThrough();
                if (fall == null || !fall.equals(cur)) {
                    break;
                }
                chain.addFirst(toScanned(prev));
                cur = prev.getAddress();
            }

            // Every suffix ending at the terminator is its own gadget.
            List<ScannedInstr> chainList = new ArrayList<>(chain);
            for (int len = 1; len <= chainList.size(); len++) {
                emit(program, chainList.subList(chainList.size() - len, chainList.size()), kind, false,
                        listing, filterLc, out, seen);
                if (out.size() >= maxResults) {
                    return true;
                }
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Byte scan: forward disassembly from every byte offset
    // -----------------------------------------------------------------------

    private boolean scanUnaligned(Program program, Listing listing, Memory memory, AddressSet scanSet,
                                  Address startAddr, Address endAddr, String term, int maxInstructions,
                                  String filterLc, int maxResults,
                                  List<Map<String, Object>> out, Set<String> seen) {
        PseudoDisassembler pseudo = new PseudoDisassembler(program);
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) {
                continue;
            }
            Address bStart = block.getStart();
            Address bEnd = block.getEnd();
            if (startAddr != null && bEnd.compareTo(startAddr) < 0) {
                continue;
            }
            if (endAddr != null && bStart.compareTo(endAddr) > 0) {
                continue;
            }
            Address scanStart = (startAddr != null && startAddr.compareTo(bStart) > 0) ? startAddr : bStart;
            Address scanEnd = (endAddr != null && endAddr.compareTo(bEnd) < 0) ? endAddr : bEnd;

            Address cursor = scanStart;
            while (cursor.compareTo(scanEnd) <= 0) {
                scanOneStart(program, pseudo, cursor, scanEnd, term, maxInstructions, filterLc,
                        listing, out, seen);
                if (out.size() >= maxResults) {
                    return true;
                }
                cursor = cursor.next();
                if (cursor == null) {
                    break;
                }
            }
        }
        return false;
    }

    /**
     * Try to grow one gadget forward from {@code start}. Emits at most one
     * gadget: the chain from start to the first matching terminator, provided
     * every instruction before it falls through to the immediately following
     * address.
     */
    private void scanOneStart(Program program, PseudoDisassembler pseudo, Address start, Address scanEnd,
                              String term, int maxInstructions, String filterLc, Listing listing,
                              List<Map<String, Object>> out, Set<String> seen) {
        List<ScannedInstr> chain = new ArrayList<>();
        // Normalization is identity on fixed/byte-aligned architectures; on
        // ARM it maps an odd offset to the aligned Thumb address with the
        // T-bit context so disassembly succeeds there.
        Address addr = PseudoDisassembler.getNormalizedDisassemblyAddress(program, start);
        for (int i = 0; i < maxInstructions; i++) {
            PseudoInstruction pi;
            byte[] bytes;
            try {
                pi = pseudo.disassemble(addr);
                bytes = pi.getBytes();
            } catch (Exception e) {
                return; // not decodable here (bad bytes, past block end, ...)
            }
            if (bytes.length == 0) {
                return;
            }
            FlowType ft = pi.getFlowType();
            // Report the chain's first instruction at the raw start offset
            // (may differ from the normalized address, e.g. odd Thumb
            // offsets); later instructions display at their real addresses.
            chain.add(new ScannedInstr(chain.isEmpty() ? start : addr,
                    pi.toString(), bytes, ft, pi.getFallThrough()));

            String kind = classifyTerminator(ft);
            if (kind != null && kindMatches(term, kind)) {
                emit(program, chain, kind, true, listing, filterLc, out, seen);
                return;
            }
            Address fall = pi.getFallThrough();
            if (fall == null) {
                return; // mid-chain terminator of a different kind, unconditional jump, ...
            }
            Address expected;
            try {
                expected = addr.add(bytes.length);
            } catch (Exception e) {
                return;
            }
            if (!fall.equals(expected) || expected.compareTo(scanEnd) > 0) {
                return;
            }
            addr = expected;
        }
    }

    // -----------------------------------------------------------------------
    // Record building
    // -----------------------------------------------------------------------

    private static ScannedInstr toScanned(Instruction instr) {
        byte[] bytes;
        try {
            bytes = instr.getBytes();
        } catch (Exception e) {
            bytes = new byte[0];
        }
        return new ScannedInstr(instr.getAddress(), instr.toString(), bytes,
                instr.getFlowType(), instr.getFallThrough());
    }

    private void emit(Program program, List<ScannedInstr> chain, String kind, boolean fromByteScan,
                      Listing listing, String filterLc, List<Map<String, Object>> out, Set<String> seen) {
        ScannedInstr first = chain.get(0);
        ScannedInstr last = chain.get(chain.size() - 1);
        String key = first.address() + "|" + last.address() + "|" + chain.size();
        if (!seen.add(key)) {
            return;
        }

        StringBuilder text = new StringBuilder();
        StringBuilder hex = new StringBuilder();
        List<String> instructions = new ArrayList<>();
        int lengthBytes = 0;
        for (ScannedInstr si : chain) {
            if (text.length() > 0) {
                text.append(" ; ");
            }
            text.append(si.text());
            instructions.add(si.address().toString(false) + ": " + si.text());
            for (byte b : si.bytes()) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            lengthBytes += si.bytes().length;
        }

        String gadgetText = text.toString();
        if (!filterLc.isEmpty() && !gadgetText.toLowerCase().contains(filterLc)) {
            return;
        }

        Map<String, Object> record = new LinkedHashMap<>();
        record.putAll(ServiceUtils.addressToJson(first.address(), program));
        record.put("terminator", kind);
        record.put("text", gadgetText);
        record.put("instructions", instructions);
        record.put("bytes", hex.toString());
        record.put("length_instructions", chain.size());
        record.put("length_bytes", lengthBytes);
        if (fromByteScan && listing.getInstructionAt(first.address()) == null) {
            // Start is not a defined instruction: an unintended gadget only
            // visible to byte-level scanning (the classic mid-instruction ROP
            // trick). Agents should prefer aligned gadgets when both exist.
            record.put("unaligned", true);
        }
        out.add(record);
    }
}
