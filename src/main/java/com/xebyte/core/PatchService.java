package com.xebyte.core;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for byte patching: raw memory writes and assembler-based patching.
 */
@McpToolGroup(value = "patching", description = "Write raw bytes to memory, patch instructions with Ghidra's built-in assembler")
public class PatchService {

    /** Matches /read_memory's 16 MB ceiling: anything you can patch you can read back in one call. */
    private static final int MAX_PATCH_BYTES = 16 * 1024 * 1024;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public PatchService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // Raw byte patching
    // -----------------------------------------------------------------------

    @McpTool(path = "/patch_bytes", method = "POST",
             description = "Write raw bytes into program memory (hex string, spaced \"90 90\" or compact \"9090\"). "
                         + "Returns the previous bytes so the patch can be reverted. The target range must lie inside "
                         + "one initialized memory block and cannot include bytes owned by a defined instruction or "
                         + "data item (Ghidra refuses those writes — use assemble to replace instructions, or "
                         + "clear_flow_and_repair first). Patching over existing code/data leaves the listing stale — "
                         + "the response warns when it does; follow up with clear_flow_and_repair or reanalyze. "
                         + "To patch code by mnemonic instead of hex, use assemble.",
             category = "patching")
    public Response patchBytes(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "bytes", source = ParamSource.BODY,
                   description = "Bytes to write as a hex string. Both spaced (\"90 90 cc\") and compact "
                               + "(\"9090cc\") forms are accepted; a single leading 0x is tolerated. "
                               + "Must decode to 1..16777216 bytes.") String bytesHex,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        byte[] bytes;
        try {
            bytes = decodeHex(bytesHex);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        Memory memory = program.getMemory();
        Address end = rangeEnd(address, bytes.length);
        if (end == null) {
            return Response.err("Patch of " + bytes.length + " bytes at " + addressStr
                    + " overflows the address space");
        }
        Response rangeError = checkRange(memory, address, end, bytes.length, addressStr);
        if (rangeError != null) {
            return rangeError;
        }

        try {
            byte[] previous = new byte[bytes.length];
            memory.getBytes(address, previous);

            int transactionId = program.startTransaction("Patch bytes");
            try {
                memory.setBytes(address, bytes);
            } finally {
                program.endTransaction(transactionId, true);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "success");
            result.putAll(ServiceUtils.addressToJson(address, program));
            result.put("end_address", end.toString(false));
            result.put("length", bytes.length);
            result.put("bytes", toHex(bytes));
            result.put("previous_bytes", toHex(previous));
            List<String> warnings = staleListingWarnings(program, address, end);
            if (!warnings.isEmpty()) {
                result.put("warnings", warnings);
            }
            return Response.ok(result);
        } catch (Exception e) {
            Msg.error(this, "Error patching bytes at " + addressStr, e);
            String msg = e.getMessage();
            if (msg != null && msg.contains("conflicts with")) {
                return Response.err("Error patching bytes: " + msg
                        + ". Raw byte writes cannot modify bytes that are part of a defined "
                        + "instruction or data item — clear the code units first "
                        + "(clear_flow_and_repair), or use assemble to replace instructions.");
            }
            return Response.err("Error patching bytes: " + msg);
        }
    }

    // -----------------------------------------------------------------------
    // Assembler patching
    // -----------------------------------------------------------------------

    @McpTool(path = "/assemble", method = "POST",
             description = "Assemble instructions with Ghidra's built-in assembler and write them into program "
                         + "memory, replacing existing code units at the address (like the GUI's Patch Instruction "
                         + "action). Pass one instruction (\"MOV EAX, 1\") or several separated by ';'. "
                         + "Returns the assembled bytes, the disassembly now at the address, and the previous "
                         + "bytes so the patch can be reverted. The target range must lie inside one initialized "
                         + "memory block. To write raw hex instead, use patch_bytes.",
             category = "patching")
    public Response assemble(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address to assemble at. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "instructions", source = ParamSource.BODY,
                   description = "Assembly text for the program's instruction set: a single instruction "
                               + "(\"NOP\") or several separated by ';' (\"MOV EAX, 1; RET\"). Syntax must "
                               + "match the disassembly listing's mnemonics.") String instructionsText,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (instructionsText == null || instructionsText.isBlank()) {
            return Response.err("instructions is required (e.g., \"NOP\" or \"MOV EAX, 1; RET\")");
        }
        List<String> lines = new ArrayList<>();
        for (String line : instructionsText.split(";")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                lines.add(trimmed);
            }
        }
        if (lines.isEmpty()) {
            return Response.err("instructions contained no instruction text");
        }

        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        Assembler assembler = Assemblers.getAssembler(program);

        // Pre-assemble each line at its final address to validate the whole
        // input and measure the range BEFORE touching the program. Branch
        // encodings are position-dependent, so line N must be measured at
        // address + length of lines 0..N-1.
        int totalLength = 0;
        try {
            Address cursor = address;
            for (String line : lines) {
                byte[] assembled = assembler.assembleLine(cursor, line);
                totalLength += assembled.length;
                cursor = cursor.add(assembled.length);
            }
        } catch (AssemblySyntaxException | AssemblySemanticException e) {
            return Response.err("Assembly failed: " + e.getMessage());
        } catch (Exception e) {
            return Response.err("Assembly failed for '" + instructionsText + "' at " + addressStr
                    + ": " + e.getMessage());
        }

        Memory memory = program.getMemory();
        Address end = rangeEnd(address, totalLength);
        if (end == null) {
            return Response.err("Assembled patch of " + totalLength + " bytes at " + addressStr
                    + " overflows the address space");
        }
        Response rangeError = checkRange(memory, address, end, totalLength, addressStr);
        if (rangeError != null) {
            return rangeError;
        }

        try {
            byte[] previous = new byte[totalLength];
            memory.getBytes(address, previous);

            int transactionId = program.startTransaction("Assemble patch");
            try {
                assembler.assemble(address, lines.toArray(new String[0]));
            } finally {
                program.endTransaction(transactionId, true);
            }

            byte[] landed = new byte[totalLength];
            memory.getBytes(address, landed);

            List<String> disassembly = new ArrayList<>();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(address, true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                if (instruction.getAddress().compareTo(end) > 0) {
                    break;
                }
                disassembly.add(instruction.getAddress().toString(false) + ": " + instruction);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "success");
            result.putAll(ServiceUtils.addressToJson(address, program));
            result.put("end_address", end.toString(false));
            result.put("length", totalLength);
            result.put("assembled_bytes", toHex(landed));
            result.put("previous_bytes", toHex(previous));
            result.put("disassembly", disassembly);
            return Response.ok(result);
        } catch (AssemblySyntaxException | AssemblySemanticException e) {
            return Response.err("Assembly failed: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "Error assembling at " + addressStr, e);
            return Response.err("Error assembling patch: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Last address of a length-byte range starting at address, or null on overflow. */
    private static Address rangeEnd(Address address, int length) {
        try {
            return address.add(length - 1L);
        } catch (Exception e) {
            return null;
        }
    }

    /** Validate that [address, end] sits inside one initialized memory block. Null means OK. */
    private static Response checkRange(Memory memory, Address address, Address end, int length,
                                       String addressStr) {
        MemoryBlock block = memory.getBlock(address);
        if (block == null) {
            return Response.err("No memory block contains address " + addressStr
                    + ". Check the address against list_segments.");
        }
        if (!block.isInitialized()) {
            return Response.err("Memory block '" + block.getName() + "' at " + addressStr
                    + " is uninitialized — there are no bytes to patch. Use create_memory_block "
                    + "with initialized=true first.");
        }
        if (!block.contains(end)) {
            return Response.err("Patch of " + length + " bytes at " + addressStr
                    + " crosses the end of memory block '" + block.getName() + "' (ends at "
                    + block.getEnd() + "). Split the patch or target a single block.");
        }
        return null;
    }

    /** Warnings to attach when the patched range overlaps defined code units. */
    private static List<String> staleListingWarnings(Program program, Address address, Address end) {
        List<String> warnings = new ArrayList<>();
        Listing listing = program.getListing();
        CodeUnitIterator codeUnits = listing.getCodeUnits(new AddressSet(address, end), true);
        int overlapped = 0;
        boolean hasInstruction = false;
        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            overlapped++;
            if (cu instanceof Instruction) {
                hasInstruction = true;
            }
        }
        if (overlapped > 0) {
            warnings.add("Patched range overlaps " + overlapped + " existing "
                    + (hasInstruction ? "instruction(s)/data" : "data")
                    + " — the listing is now stale. Run clear_flow_and_repair or reanalyze "
                    + "to disassemble the new bytes.");
        }
        return warnings;
    }

    /**
     * Decode a hex string accepting spaced ("90 90"), compact ("9090"), and
     * 0x-prefixed forms. Commas and underscores are tolerated as separators.
     */
    static byte[] decodeHex(String hex) {
        if (hex == null || hex.isBlank()) {
            throw new IllegalArgumentException("bytes is required (hex string, e.g., \"90 90\" or \"9090\")");
        }
        String cleaned = hex.replaceAll("[\\s,_]+", "");
        if (cleaned.length() >= 2 && cleaned.charAt(0) == '0'
                && (cleaned.charAt(1) == 'x' || cleaned.charAt(1) == 'X')) {
            cleaned = cleaned.substring(2);
        }
        if (cleaned.isEmpty()) {
            throw new IllegalArgumentException("bytes contained no hex digits");
        }
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("bytes must have an even number of hex digits (got "
                    + cleaned.length() + ")");
        }
        if (cleaned.length() / 2 > MAX_PATCH_BYTES) {
            throw new IllegalArgumentException("bytes decodes to " + (cleaned.length() / 2)
                    + " bytes, over the " + MAX_PATCH_BYTES + "-byte limit");
        }
        byte[] out = new byte[cleaned.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(cleaned.charAt(i * 2), 16);
            int lo = Character.digit(cleaned.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bytes is not valid hex: bad character near position "
                        + (hi < 0 ? i * 2 : i * 2 + 1) + " of \"" + cleaned + "\"");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
