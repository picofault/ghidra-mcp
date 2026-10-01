package com.xebyte.core;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * MCP endpoints for targeted function emulation via Ghidra's P-code emulator.
 *
 * <p>Designed for API hash resolution: emulate a hash function with controlled
 * inputs (candidate API name string in memory, hash parameters in registers)
 * and read the computed hash from the output register. No full process needed —
 * the emulator runs the function's P-code in isolation.</p>
 *
 * <h3>Typical agent workflow for API hash resolution</h3>
 * <pre>{@code
 * 1. decompile_function(hash_func_addr) → understand calling convention
 * 2. get_function_variables(hash_func) → identify input/output registers
 * 3. emulate_function(hash_func_addr, registers={ECX: string_ptr},
 *        memory=[{addr: string_ptr, data: "CreateProcessW\0"}])
 *    → returns {EAX: 0x7C0DFCAA}
 * 4. Compare 0x7C0DFCAA against target hash → match!
 * 5. batch_set_comments(hash_call_addr, "Resolved: CreateProcessW")
 * }</pre>
 *
 * <h3>Batch mode for brute-forcing</h3>
 * <pre>{@code
 * emulate_hash_batch(hash_func_addr, register_template={ECX: "${STRING_PTR}"},
 *     candidates=["CreateProcessW", "VirtualAlloc", "LoadLibraryA", ...],
 *     target_hash=0x7C0DFCAA, result_register="EAX")
 *   → returns {matched: "CreateProcessW", hash: 0x7C0DFCAA, iterations: 42}
 * }</pre>
 *
 * <h3>Interactive-style execution from any address</h3>
 * <p>{@code emulate_execute} starts the emulator at ANY address (not just
 * function entries), seeds registers and memory from JSON, stops at a
 * breakpoint address / RET sentinel / instruction cap, and reports exactly the
 * register and memory state requested — for string-decryption routines, ROP
 * gadget dry-runs, and debugger-free return-value evaluation.</p>
 *
 * @since 5.4.0
 */
@McpToolGroup(value = "emulation",
        description = "Targeted function emulation for hash resolution, crypto analysis, " +
                "and controlled execution of isolated code paths")
public class EmulationService {

    private static final int DEFAULT_TIMEOUT_MS = 10_000;
    private static final int DEFAULT_MAX_STEPS = 10_000;
    private static final int MAX_STEPS = 100_000;
    private static final int MAX_CANDIDATES = 10_000;
    // Scratch memory for writing candidate strings during emulation
    private static final long SCRATCH_BASE = 0x7FFE0000L;
    private static final int SCRATCH_SIZE = 0x10000;
    // emulate_execute limits and defaults
    private static final int DEFAULT_MAX_INSTRUCTIONS = 1_000;
    private static final int MAX_READ_BACK_BYTES = 0x10000;
    private static final int MAX_WRITTEN_RANGES = 256;
    private static final long DEFAULT_STACK_OFFSET = 0x7FFF0000L;
    private static final long RETURN_SENTINEL_32 = 0xDEADBEEFL;
    private static final long RETURN_SENTINEL_64 = 0xDEADBEEFDEADBEEFL;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public EmulationService(ProgramProvider programProvider,
                            ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // ========================================================================
    // Single-function emulation
    // ========================================================================

    /**
     * Emulate a function with controlled inputs and return the final state.
     *
     * <p>Sets up the P-code emulator with the specified register values and
     * memory contents, runs the function until RET or step limit, and returns
     * all register values at completion.</p>
     */
    @McpTool(path = "/emulate_function", method = "POST",
            description = "Emulate a single function with controlled register/memory inputs. " +
                    "Returns final register state after execution. Ideal for understanding " +
                    "hash functions, crypto routines, or any pure-computation code path.",
            category = "emulation")
    public Response emulateFunction(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                    description = "Entry point address of the function to emulate") String addressStr,
            @Param(value = "registers", source = ParamSource.BODY, fieldsJson = true,
                    description = "Initial register values as JSON: {\"EAX\": \"0x1234\", \"ECX\": \"0x7FFE0000\"}") String registersJson,
            @Param(value = "memory", source = ParamSource.BODY, fieldsJson = true,
                    description = "Memory regions to pre-populate as JSON array: [{\"address\": \"0x7FFE0000\", \"data\": \"base64...\"}] " +
                            "or [{\"address\": \"0x7FFE0000\", \"string\": \"CreateProcessW\\u0000\"}]") String memoryJson,
            @Param(value = "max_steps", source = ParamSource.BODY, defaultValue = "10000",
                    description = "Maximum P-code steps before timeout") int maxSteps,
            @Param(value = "return_registers", source = ParamSource.BODY, defaultValue = "",
                    description = "Comma-separated register names to return (empty = all general-purpose)") String returnRegisters,
            @Param(value = "read_memory_after", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "",
                    description = "Memory regions to read back AFTER emulation, as a JSON array: " +
                            "[{\"address\": \"0x408300\", \"length\": 16}, ...]. Needed to observe " +
                            "in-place mutations (e.g. a function that lowercases a string via a " +
                            "pointer argument) -- the emulator's memory is an ISOLATED overlay and " +
                            "never touches the real program, so a plain read_memory call after " +
                            "emulation sees only the ORIGINAL unmodified bytes, not the emulated " +
                            "result. This reads from the emulator's own state instead.")
                    String readMemoryAfterJson,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, addressStr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + addressStr);

        try {
            EmulatorHelper emu = new EmulatorHelper(program);
            try {
                // Set up stack pointer
                Address stackAddr = program.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(0x7FFF0000L);
                emu.writeRegister("ESP", stackAddr.getOffset());
                emu.writeRegister("EBP", stackAddr.getOffset());

                // Write a return address to the stack (so RET has somewhere to go)
                long returnSentinel = 0xDEADBEEFL;
                byte[] retAddrBytes = ByteBuffer.allocate(4)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .putInt((int) returnSentinel).array();
                emu.writeMemory(stackAddr, retAddrBytes);

                // Apply user-specified register values
                if (registersJson != null && !registersJson.isEmpty()) {
                    Map<String, Object> regs = JsonHelper.parseJson(registersJson);
                    for (Map.Entry<String, Object> entry : regs.entrySet()) {
                        String regName = entry.getKey();
                        long value = parseLongValue(String.valueOf(entry.getValue()));
                        emu.writeRegister(regName, value);
                    }
                }

                // Apply user-specified memory contents
                if (memoryJson != null && !memoryJson.isEmpty()) {
                    List<Map<String, String>> regions = ServiceUtils.convertToMapList(
                            JsonHelper.parseJson(memoryJson).get("regions"));
                    if (regions == null) {
                        // Try parsing as a direct array
                        regions = ServiceUtils.convertToMapList(memoryJson);
                    }
                    if (regions != null) {
                        for (Map<String, String> region : regions) {
                            String addrStr = String.valueOf(region.get("address"));
                            Address memAddr = ServiceUtils.parseAddress(program, addrStr);
                            if (memAddr == null) continue;

                            if (region.containsKey("string")) {
                                // Write a null-terminated string
                                String str = String.valueOf(region.get("string"));
                                byte[] strBytes = (str + "\0").getBytes("UTF-8");
                                emu.writeMemory(memAddr, strBytes);
                            } else if (region.containsKey("data")) {
                                // Write base64-encoded bytes
                                String b64 = String.valueOf(region.get("data"));
                                byte[] data = Base64.getDecoder().decode(b64);
                                emu.writeMemory(memAddr, data);
                            } else if (region.containsKey("hex")) {
                                // Write hex-encoded bytes
                                String hex = String.valueOf(region.get("hex"));
                                byte[] data = hexToBytes(hex);
                                emu.writeMemory(memAddr, data);
                            }
                        }
                    }
                }

                // Run emulation with a hard step bound. emu.run(...) is
                // unbounded — it loops until a breakpoint or fault — so a
                // target with an infinite loop (or one that never executes
                // RET to hit the returnSentinel) would hang the HTTP
                // handler thread forever. Step explicitly so the advertised
                // max_steps parameter is actually honored.
                int effectiveMaxSteps = Math.min(
                        maxSteps > 0 ? maxSteps : DEFAULT_MAX_STEPS, MAX_STEPS);
                ghidra.util.task.TaskMonitor monitor =
                        new ghidra.util.task.ConsoleTaskMonitor();

                // Position PC at the entry point, then step.
                emu.writeRegister(emu.getPCRegister(), entryAddr.getOffset());

                int steps = 0;
                boolean success = true;
                boolean hitReturn = false;
                String stopReason = "max_steps_exceeded";
                Address pc = null;
                while (steps < effectiveMaxSteps) {
                    steps++;
                    if (!emu.step(monitor)) {
                        success = false;
                        stopReason = "fault: " + emu.getLastError();
                        break;
                    }
                    pc = emu.getExecutionAddress();
                    if (pc != null && pc.getOffset() == returnSentinel) {
                        hitReturn = true;
                        stopReason = "return";
                        break;
                    }
                }
                if (steps >= effectiveMaxSteps && !hitReturn && success) {
                    // Step cap reached without RET or fault — likely an
                    // infinite loop or a path that never returns.
                    success = false;
                }

                // Collect results
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", success);
                result.put("function", func.getName());
                result.put("entry_address", entryAddr.toString());
                result.put("steps_executed", steps);
                result.put("max_steps", effectiveMaxSteps);
                result.put("stop_reason", stopReason);

                pc = emu.getExecutionAddress();
                result.put("final_pc", pc != null ? pc.toString() : "unknown");
                result.put("hit_return", hitReturn);

                // Read registers
                Map<String, String> regValues = new LinkedHashMap<>();
                if (returnRegisters != null && !returnRegisters.isEmpty()) {
                    for (String rn : returnRegisters.split(",")) {
                        rn = rn.trim();
                        try {
                            BigInteger val = emu.readRegister(rn);
                            regValues.put(rn, "0x" + val.toString(16));
                        } catch (Exception e) {
                            regValues.put(rn, "error: " + e.getMessage());
                        }
                    }
                } else {
                    // Return common general-purpose registers
                    for (String rn : new String[]{"EAX", "EBX", "ECX", "EDX",
                            "ESI", "EDI", "ESP", "EBP", "EIP"}) {
                        try {
                            BigInteger val = emu.readRegister(rn);
                            regValues.put(rn, "0x" + val.toString(16));
                        } catch (Exception ignored) {
                            // Register may not exist for this architecture
                        }
                    }
                }
                result.put("registers", regValues);

                // Read back caller-specified memory regions from the EMULATOR's
                // state (not the program's), so a mutation made only inside the
                // sandboxed run -- e.g. a string lowercased in place via a
                // pointer argument -- is observable. Read even on a fault or
                // step-limit exit: a partial mutation up to the point of failure
                // is still useful evidence for a caller diagnosing why two
                // implementations disagree.
                if (readMemoryAfterJson != null && !readMemoryAfterJson.isEmpty()) {
                    List<Map<String, String>> regions = ServiceUtils.convertToMapList(
                            JsonHelper.parseJson(readMemoryAfterJson).get("regions"));
                    if (regions == null) {
                        regions = ServiceUtils.convertToMapList(readMemoryAfterJson);
                    }
                    if (regions != null) {
                        List<Map<String, Object>> memResults = new ArrayList<>();
                        for (Map<String, String> region : regions) {
                            String addrStr = String.valueOf(region.get("address"));
                            Map<String, Object> entry = new LinkedHashMap<>();
                            entry.put("address", addrStr);
                            Address memAddr = ServiceUtils.parseAddress(program, addrStr);
                            // Gson parses JSON numbers as Double, so a naive
                            // Integer.decode(String.valueOf(...)) sees "16.0"
                            // and throws -- JsonHelper.getInt already exists
                            // to handle Double/Integer/Long/String uniformly.
                            int length = JsonHelper.getInt(region.get("length"), 0);
                            if (memAddr == null || length <= 0) {
                                entry.put("error", "invalid address or length");
                            } else {
                                try {
                                    byte[] readBack = emu.readMemory(memAddr, length);
                                    StringBuilder hex = new StringBuilder(readBack.length * 2);
                                    for (byte b : readBack) {
                                        hex.append(String.format("%02x", b));
                                    }
                                    entry.put("hex", hex.toString());
                                } catch (Exception e) {
                                    entry.put("error", e.getMessage());
                                }
                            }
                            memResults.add(entry);
                        }
                        result.put("memory", memResults);
                    }
                }

                String lastError = emu.getLastError();
                if (lastError != null && !lastError.isEmpty()) {
                    result.put("emulation_error", lastError);
                }

                return Response.ok(result);
            } finally {
                emu.dispose();
            }
        } catch (Exception e) {
            return Response.err("Emulation failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Interactive-style execution from any address
    // ========================================================================

    /**
     * Execute code from any start address with controlled register/memory
     * inputs and observe the resulting state. Unlike {@link #emulateFunction}
     * this is not function-centric: the start address may be mid-function (a
     * gadget), there is no function lookup, and the response reports only the
     * state the caller asked for.
     */
    @McpTool(path = "/emulate_execute", method = "POST",
            description = "Execute code from any start address in the P-code emulator with controlled " +
                    "registers and memory, then read back the resulting state. Three target workflows: " +
                    "(1) run an obfuscated string-decryption routine — seed the encrypted buffer with " +
                    "memory_writes, set its pointer/length argument registers, stop at end_address or RET, " +
                    "and read the decoded buffer back with read_memory (each entry has an ascii rendering); " +
                    "(2) dry-run a ROP gadget or short code sequence — seed the stack with memory_writes, " +
                    "set registers, and observe exactly which registers and memory change (track_writes " +
                    "reports every memory range the code wrote); (3) evaluate a function's return value " +
                    "for given arguments without a debugger — set argument registers per the ABI (x86-64 " +
                    "SysV: RDI, RSI, RDX, RCX, R8, R9) and read RAX once stop_reason is 'return'. A stack " +
                    "pointer and return-address sentinel are pre-seeded so a RET ends the run; end_address " +
                    "stops BEFORE the instruction there executes. Fully sandboxed: the emulator works on a " +
                    "private copy of program memory and NEVER mutates the program, its listing, or its " +
                    "database. Memory the code reads but you did not seed (and that is not initialized " +
                    "program bytes) reads back as 0 — seed every input with memory_writes. Use " +
                    "emulate_function instead for the classic hash-function workflow with a full " +
                    "general-purpose register dump.",
            category = "emulation")
    public Response emulateExecute(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                    description = "Start execution address: 0x<hex> or <space>:<hex>. Need not be a function " +
                            "entry — any decodable address works (mid-function gadget, stub). Note: some " +
                            "programs — particularly embedded/microcontroller targets — are not " +
                            "address-space-agnostic; use get_address_spaces to discover spaces before " +
                            "assuming a plain hex address is unambiguous.") String addressStr,
            @Param(value = "registers", source = ParamSource.BODY, fieldsJson = true, defaultValue = "",
                    description = "Register values to set before execution, as a JSON object: " +
                            "{\"RDI\": \"0x7ffe0000\", \"RSI\": \"16\"} — values are hex strings (0x...) " +
                            "or decimal. Unknown register names are rejected with valid examples. Applied " +
                            "after the default stack-pointer setup, so an explicitly seeded stack pointer " +
                            "wins.") String registersJson,
            @Param(value = "memory_writes", source = ParamSource.BODY, fieldsJson = true, defaultValue = "",
                    description = "Memory to seed before execution, as a JSON array: " +
                            "[{\"address\": \"0x7ffe0000\", \"bytes\": \"41424300\"}] — bytes is a hex " +
                            "string (optional 0x prefix, spaces ignored). Use for encrypted string " +
                            "buffers, fake stack contents, or structure inputs. Addresses outside the " +
                            "program's address spaces are rejected; unmapped-but-in-space addresses are " +
                            "fine (emulator memory is allocated on demand).") String memoryWritesJson,
            @Param(value = "end_address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                    description = "Optional stop address: execution halts BEFORE the instruction at this " +
                            "address runs (debugger-style breakpoint), reported as stop_reason " +
                            "'end_address'.") String endAddressStr,
            @Param(value = "max_instructions", source = ParamSource.BODY, defaultValue = "1000",
                    description = "Maximum instructions to execute (default 1000, hard cap 100000). " +
                            "Reaching the cap yields stop_reason 'max_instructions' with all state up to " +
                            "that point intact — raise it for loops, lower it to bound a gadget dry-run.") int maxInstructions,
            @Param(value = "read_registers", source = ParamSource.BODY, defaultValue = "",
                    description = "Registers to report after the run: comma-separated (\"RAX,RDI\") or a " +
                            "JSON array ([\"RAX\",\"RDI\"]). Empty reports the architecture's " +
                            "general-purpose base registers (e.g. x86-64: RAX..R15, RBP, RSP, RIP, " +
                            "RFLAGS).") String readRegisters,
            @Param(value = "read_memory", source = ParamSource.BODY, fieldsJson = true, defaultValue = "",
                    description = "Memory to read back from the EMULATOR's post-run state, as a JSON " +
                            "array: [{\"address\": \"0x7ffe0000\", \"length\": 64}] — max 65536 bytes per " +
                            "region. Each entry returns hex plus a best-effort ascii rendering (printable " +
                            "bytes, '.' otherwise) for string-decryption results. Read even when the run " +
                            "faults, so partial mutations remain visible. A plain read_memory call " +
                            "afterwards would show the ORIGINAL program bytes, not the emulated result.") String readMemoryJson,
            @Param(value = "track_writes", source = ParamSource.BODY, defaultValue = "false",
                    description = "true: record every memory range the emulated code writes and report " +
                            "them as written_memory — answers 'what did this code touch?' for gadget and " +
                            "decoder analysis. Register writes are not tracked (no Ghidra API for it); " +
                            "diff read_registers against your seeded registers instead.") boolean trackWrites,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isBlank()) {
            return Response.err("address is required (start execution address, 0x<hex> or <space>:<hex>)");
        }
        Address startAddr = ServiceUtils.parseAddress(program, addressStr);
        if (startAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Address endAddr = null;
        if (endAddressStr != null && !endAddressStr.isBlank()) {
            endAddr = ServiceUtils.parseAddress(program, endAddressStr);
            if (endAddr == null) return Response.err(ServiceUtils.getLastParseError());
        }

        int effectiveMax = maxInstructions > 0
                ? Math.min(maxInstructions, MAX_STEPS) : DEFAULT_MAX_INSTRUCTIONS;

        // Validate register seeds up front: an unknown name or bad value is an
        // input error, and failing before the run beats a half-executed state.
        Map<String, Long> seedRegs = new LinkedHashMap<>();
        if (registersJson != null && !registersJson.isBlank()) {
            Map<String, Object> parsed = JsonHelper.parseJson(registersJson);
            for (Map.Entry<String, Object> entry : parsed.entrySet()) {
                String regName = entry.getKey().trim();
                if (program.getRegister(regName) == null) {
                    return Response.err("Unknown register '" + regName + "' for language "
                            + program.getLanguageID() + ". Example valid registers: "
                            + String.join(", ", defaultReadRegisterNames(program, 8)));
                }
                Long value = parseNumericValue(entry.getValue());
                if (value == null) {
                    return Response.err("Invalid value for register '" + regName + "': '"
                            + entry.getValue() + "' — use a hex string (\"0x...\") or decimal.");
                }
                seedRegs.put(regName, value);
            }
        }

        // Validate memory seeds (all parsing happens on this thread — the
        // parseAddress error channel is a ThreadLocal).
        List<Map<String, Object>> memWrites = new ArrayList<>();
        if (memoryWritesJson != null && !memoryWritesJson.isBlank()) {
            List<Map<String, String>> regions = parseRegionList(memoryWritesJson);
            if (regions == null || regions.isEmpty()) {
                return Response.err("memory_writes must be a JSON array of " +
                        "{\"address\": \"0x...\", \"bytes\": \"<hex>\"} entries");
            }
            int idx = 0;
            for (Map<String, String> region : regions) {
                idx++;
                String addrStr = region.get("address");
                String bytesStr = region.get("bytes");
                if (addrStr == null || bytesStr == null) {
                    return Response.err("memory_writes entry " + idx + " needs both \"address\" " +
                            "and \"bytes\" (hex string)");
                }
                Address memAddr = ServiceUtils.parseAddress(program, addrStr);
                if (memAddr == null) {
                    return Response.err("memory_writes entry " + idx + ": "
                            + ServiceUtils.getLastParseError());
                }
                String hex = bytesStr.replace(" ", "").replace("0x", "").replace("0X", "");
                if (hex.isEmpty() || hex.length() % 2 != 0) {
                    return Response.err("memory_writes entry " + idx + ": \"bytes\" must be an " +
                            "even-length hex string (got '" + bytesStr + "')");
                }
                byte[] data;
                try {
                    data = hexToBytes(hex);
                } catch (NumberFormatException e) {
                    return Response.err("memory_writes entry " + idx + ": invalid hex in \"bytes\": '"
                            + bytesStr + "'");
                }
                Map<String, Object> write = new LinkedHashMap<>();
                write.put("address", memAddr);
                write.put("data", data);
                memWrites.add(write);
            }
        }

        // Validate read-back regions up front too (same ThreadLocal rationale).
        List<Map<String, Object>> readBacks = new ArrayList<>();
        if (readMemoryJson != null && !readMemoryJson.isBlank()) {
            List<Map<String, String>> regions = parseRegionList(readMemoryJson);
            if (regions == null || regions.isEmpty()) {
                return Response.err("read_memory must be a JSON array of " +
                        "{\"address\": \"0x...\", \"length\": N} entries");
            }
            int idx = 0;
            for (Map<String, String> region : regions) {
                idx++;
                String addrStr = region.get("address");
                int length = JsonHelper.getInt(region.get("length"), 0);
                if (addrStr == null) {
                    return Response.err("read_memory entry " + idx + " needs \"address\"");
                }
                Address memAddr = ServiceUtils.parseAddress(program, addrStr);
                if (memAddr == null) {
                    return Response.err("read_memory entry " + idx + ": "
                            + ServiceUtils.getLastParseError());
                }
                if (length <= 0 || length > MAX_READ_BACK_BYTES) {
                    return Response.err("read_memory entry " + idx + ": length must be 1.."
                            + MAX_READ_BACK_BYTES + " (got " + region.get("length") + ")");
                }
                Map<String, Object> read = new LinkedHashMap<>();
                read.put("address", memAddr);
                read.put("length", length);
                readBacks.add(read);
            }
        }

        // Registers to report: explicit list, or the architecture's default set.
        List<String> readRegNames = new ArrayList<>();
        if (readRegisters != null && !readRegisters.isBlank()) {
            String trimmed = readRegisters.trim();
            if (trimmed.startsWith("[")) {
                Object arr = JsonHelper.parseJson("{\"r\":" + trimmed + "}").get("r");
                if (arr instanceof List<?> list) {
                    for (Object item : list) {
                        readRegNames.add(String.valueOf(item).trim());
                    }
                }
            } else {
                for (String rn : trimmed.split(",")) {
                    if (!rn.isBlank()) readRegNames.add(rn.trim());
                }
            }
            for (String rn : readRegNames) {
                if (program.getRegister(rn) == null) {
                    return Response.err("Unknown register '" + rn + "' in read_registers for language "
                            + program.getLanguageID() + ". Example valid registers: "
                            + String.join(", ", defaultReadRegisterNames(program, 8)));
                }
            }
        } else {
            readRegNames.addAll(defaultReadRegisterNames(program, Integer.MAX_VALUE));
        }

        try {
            EmulatorHelper emu = new EmulatorHelper(program);
            try {
                AddressSpace defSpace = program.getAddressFactory().getDefaultAddressSpace();
                int ptrSize = program.getDefaultPointerSize();
                boolean bigEndian = program.getLanguage().isBigEndian();
                long returnSentinel = ptrSize > 4 ? RETURN_SENTINEL_64 : RETURN_SENTINEL_32;

                // Pre-seed a stack pointer and a return-address sentinel so a
                // RET ends the run instead of decoding garbage. Applied FIRST:
                // caller-supplied registers and memory_writes below win.
                Register sp = emu.getStackPointerRegister();
                if (sp != null) {
                    Address stackAddr = defSpace.getAddress(DEFAULT_STACK_OFFSET);
                    emu.writeRegister(sp, BigInteger.valueOf(DEFAULT_STACK_OFFSET));
                    emu.writeMemory(stackAddr, pointerBytes(returnSentinel, ptrSize, bigEndian));
                }

                for (Map.Entry<String, Long> entry : seedRegs.entrySet()) {
                    emu.writeRegister(entry.getKey(), BigInteger.valueOf(entry.getValue()));
                }
                for (Map<String, Object> write : memWrites) {
                    emu.writeMemory((Address) write.get("address"), (byte[]) write.get("data"));
                }

                // Enable tracking only after seeding so the caller's own setup
                // writes do not show up in written_memory.
                if (trackWrites) {
                    emu.enableMemoryWriteTracking(true);
                }

                emu.writeRegister(emu.getPCRegister(), startAddr.getOffset());
                ghidra.util.task.TaskMonitor monitor = new ghidra.util.task.ConsoleTaskMonitor();

                // emu.run(...) is unbounded (loops until breakpoint/fault), so
                // step explicitly to honor max_instructions — same pattern as
                // emulate_function.
                int steps = 0;
                String stopReason;
                if (startAddr.equals(endAddr)) {
                    stopReason = "end_address";
                } else {
                    stopReason = "max_instructions";
                    while (steps < effectiveMax) {
                        steps++;
                        if (!emu.step(monitor)) {
                            stopReason = "fault";
                            break;
                        }
                        Address pc = emu.getExecutionAddress();
                        if (endAddr != null && endAddr.equals(pc)) {
                            stopReason = "end_address";
                            break;
                        }
                        if (pc != null && pc.getAddressSpace().equals(defSpace)
                                && pc.getOffset() == returnSentinel) {
                            stopReason = "return";
                            break;
                        }
                    }
                }

                boolean success = !"fault".equals(stopReason);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", success);
                result.put("start_address", startAddr.toString());
                result.put("stop_reason", stopReason);
                result.put("instructions_executed", steps);
                result.put("max_instructions", effectiveMax);
                Address pc = emu.getExecutionAddress();
                result.put("final_pc", pc != null ? pc.toString() : "unknown");
                if (endAddr != null) {
                    result.put("end_address", endAddr.toString());
                }

                Map<String, String> regValues = new LinkedHashMap<>();
                for (String rn : readRegNames) {
                    try {
                        BigInteger val = emu.readRegister(rn);
                        regValues.put(rn, "0x" + val.toString(16));
                    } catch (Exception e) {
                        regValues.put(rn, "error: " + e.getMessage());
                    }
                }
                result.put("registers", regValues);

                // Read back from the EMULATOR's state (not the program's) even
                // on fault — partial mutations are useful evidence.
                if (!readBacks.isEmpty()) {
                    List<Map<String, Object>> memResults = new ArrayList<>();
                    for (Map<String, Object> read : readBacks) {
                        Address memAddr = (Address) read.get("address");
                        int length = (Integer) read.get("length");
                        Map<String, Object> entry = new LinkedHashMap<>();
                        entry.put("address", memAddr.toString());
                        entry.put("length", length);
                        try {
                            byte[] readBack = emu.readMemory(memAddr, length);
                            entry.put("hex", bytesToHex(readBack));
                            entry.put("ascii", toAscii(readBack));
                        } catch (Exception e) {
                            entry.put("error", e.getMessage());
                        }
                        memResults.add(entry);
                    }
                    result.put("memory", memResults);
                }

                if (trackWrites) {
                    List<String> ranges = new ArrayList<>();
                    boolean truncated = false;
                    AddressSetView writeSet = emu.getTrackedMemoryWriteSet();
                    if (writeSet != null) {
                        for (AddressRange range : writeSet) {
                            // The access filter tracks every space, including
                            // the register space (p-code writes RSP/RIP there);
                            // written_memory means PROGRAM memory only.
                            if (!range.getMinAddress().getAddressSpace().isMemorySpace()) {
                                continue;
                            }
                            if (ranges.size() >= MAX_WRITTEN_RANGES) {
                                truncated = true;
                                break;
                            }
                            ranges.add(range.getMinAddress() + "-" + range.getMaxAddress());
                        }
                    }
                    Map<String, Object> written = new LinkedHashMap<>();
                    written.put("ranges", ranges);
                    written.put("truncated", truncated);
                    result.put("written_memory", written);
                }

                String lastError = emu.getLastError();
                if (lastError != null && !lastError.isEmpty()) {
                    result.put("emulation_error", lastError);
                }

                return Response.ok(result);
            } finally {
                emu.dispose();
            }
        } catch (Exception e) {
            Msg.error(this, "emulate_execute failed", e);
            return Response.err("emulate_execute failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Batch hash resolution
    // ========================================================================

    /**
     * Brute-force API hash resolution by emulating a hash function with
     * a list of candidate API name strings.
     *
     * <p>For each candidate, writes the string to scratch memory, sets the
     * string pointer register, emulates the hash function, reads the result
     * register, and compares against the target hash. Stops on first match
     * or after exhausting all candidates.</p>
     */
    @McpTool(path = "/emulate_hash_batch", method = "POST",
            description = "Brute-force API hash resolution. Emulates a hash function with " +
                    "each candidate API name and returns the one that produces the target hash. " +
                    "Ideal for resolving ROR13, CRC32, djb2, FNV, and custom hash algorithms.",
            category = "emulation")
    public Response emulateHashBatch(
            @Param(value = "hash_function_address", paramType = "address", source = ParamSource.BODY,
                    description = "Address of the hash computation function") String hashFuncAddr,
            @Param(value = "string_register", source = ParamSource.BODY,
                    description = "Register that receives the pointer to the API name string (e.g., ECX, RCX, EDI)") String stringRegister,
            @Param(value = "result_register", source = ParamSource.BODY, defaultValue = "EAX",
                    description = "Register that contains the computed hash after emulation (e.g., EAX, RAX)") String resultRegister,
            @Param(value = "target_hash", source = ParamSource.BODY,
                    description = "Target hash value to match (hex string like 0x7C0DFCAA)") String targetHashStr,
            @Param(value = "candidates", source = ParamSource.BODY, fieldsJson = true,
                    description = "JSON array of candidate API name strings: [\"CreateProcessW\", \"VirtualAlloc\", ...]") String candidatesJson,
            @Param(value = "initial_registers", source = ParamSource.BODY, fieldsJson = true, defaultValue = "",
                    description = "Additional register values to set before each emulation (JSON object)") String initialRegistersJson,
            @Param(value = "wide_string", source = ParamSource.BODY, defaultValue = "false",
                    description = "Write candidate strings as UTF-16LE (wide) instead of ASCII") boolean wideString,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address entryAddr = ServiceUtils.parseAddress(program, hashFuncAddr);
        if (entryAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = program.getFunctionManager().getFunctionAt(entryAddr);
        if (func == null) return Response.err("No function at address: " + hashFuncAddr);

        long targetHash;
        try {
            targetHash = parseLongValue(targetHashStr);
        } catch (Exception e) {
            return Response.err("Invalid target_hash: " + targetHashStr);
        }

        // Parse candidates
        List<String> candidates = new ArrayList<>();
        if (candidatesJson != null && !candidatesJson.isEmpty()) {
            try {
                Object parsed = JsonHelper.parseJson("{\"c\":" + candidatesJson + "}").get("c");
                if (parsed instanceof List<?> list) {
                    for (Object item : list) {
                        candidates.add(String.valueOf(item));
                    }
                }
            } catch (Exception e) {
                return Response.err("Invalid candidates JSON: " + e.getMessage());
            }
        }
        if (candidates.isEmpty()) {
            return Response.err("No candidates provided");
        }
        if (candidates.size() > MAX_CANDIDATES) {
            return Response.err("Too many candidates (max " + MAX_CANDIDATES + ")");
        }

        // Parse additional registers
        Map<String, Long> extraRegs = new LinkedHashMap<>();
        if (initialRegistersJson != null && !initialRegistersJson.isEmpty()) {
            Map<String, Object> parsed = JsonHelper.parseJson(initialRegistersJson);
            for (Map.Entry<String, Object> entry : parsed.entrySet()) {
                extraRegs.put(entry.getKey(), parseLongValue(String.valueOf(entry.getValue())));
            }
        }

        try {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function", func.getName());
            result.put("target_hash", "0x" + Long.toHexString(targetHash));
            result.put("total_candidates", candidates.size());

            Address scratchAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(SCRATCH_BASE);
            Address stackAddr = program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(0x7FFF0000L);
            long returnSentinel = 0xDEADBEEFL;

            List<Map<String, String>> matches = new ArrayList<>();
            int tested = 0;

            for (String candidate : candidates) {
                tested++;
                EmulatorHelper emu = new EmulatorHelper(program);
                try {
                    // Set up stack
                    emu.writeRegister("ESP", stackAddr.getOffset());
                    emu.writeRegister("EBP", stackAddr.getOffset());
                    byte[] retBytes = ByteBuffer.allocate(4)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putInt((int) returnSentinel).array();
                    emu.writeMemory(stackAddr, retBytes);

                    // Write candidate string to scratch memory
                    byte[] strBytes;
                    if (wideString) {
                        strBytes = (candidate + "\0").getBytes("UTF-16LE");
                    } else {
                        strBytes = (candidate + "\0").getBytes("US-ASCII");
                    }
                    emu.writeMemory(scratchAddr, strBytes);

                    // Set string pointer register
                    emu.writeRegister(stringRegister, SCRATCH_BASE);

                    // Set additional registers
                    for (Map.Entry<String, Long> entry : extraRegs.entrySet()) {
                        emu.writeRegister(entry.getKey(), entry.getValue());
                    }

                    // Set breakpoint at return sentinel
                    emu.setBreakpoint(program.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(returnSentinel));

                    // Run
                    emu.run(entryAddr, null, new ghidra.util.task.ConsoleTaskMonitor());

                    // Read result register
                    BigInteger hashResult = emu.readRegister(resultRegister);
                    long computedHash = hashResult.longValue() & 0xFFFFFFFFL; // mask to 32-bit

                    if (computedHash == (targetHash & 0xFFFFFFFFL)) {
                        Map<String, String> match = new LinkedHashMap<>();
                        match.put("api_name", candidate);
                        match.put("computed_hash", "0x" + Long.toHexString(computedHash));
                        match.put("iteration", String.valueOf(tested));
                        matches.add(match);
                        // Continue to find ALL matches (some hash functions have collisions)
                    }
                } finally {
                    emu.dispose();
                }
            }

            result.put("tested", tested);
            result.put("matches", matches);
            result.put("resolved", !matches.isEmpty());
            if (!matches.isEmpty()) {
                result.put("best_match", matches.get(0).get("api_name"));
            }

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Batch emulation failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static long parseLongValue(String s) {
        if (s == null || s.isEmpty()) return 0;
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseLong(s);
    }

    /**
     * Parse a register value from a parsed-JSON node: a JSON number (Gson
     * yields Double), a {@code 0x<hex>} string, or a decimal string.
     * Returns {@code null} on malformed input.
     */
    private static Long parseNumericValue(Object v) {
        if (v instanceof Number n) {
            return n.longValue();
        }
        if (v == null) {
            return null;
        }
        String s = String.valueOf(v).trim();
        if (s.isEmpty()) {
            return null;
        }
        try {
            boolean negative = s.startsWith("-");
            String body = negative ? s.substring(1) : s;
            long magnitude;
            if (body.length() > 2 && body.charAt(0) == '0'
                    && (body.charAt(1) == 'x' || body.charAt(1) == 'X')) {
                magnitude = Long.parseUnsignedLong(body.substring(2), 16);
            } else {
                magnitude = Long.parseLong(body, 10);
            }
            return negative ? -magnitude : magnitude;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Parse a regions parameter accepting either a bare JSON array or an
     * object with a {@code "regions"} key — the two shapes callers already
     * use for emulate_function's memory params.
     */
    private static List<Map<String, String>> parseRegionList(String json) {
        List<Map<String, String>> regions = ServiceUtils.convertToMapList(
                JsonHelper.parseJson(json).get("regions"));
        if (regions == null) {
            regions = ServiceUtils.convertToMapList(json);
        }
        return regions;
    }

    /**
     * The registers reported when read_registers is empty: a curated
     * general-purpose set per processor family (integer GP regs, SP, PC,
     * flags), falling back to the language's non-hidden, non-context, non-FP,
     * non-vector base registers for unlisted processors. Curated because the
     * generic base-register filter alone passes 100+ x86 system registers
     * (CR*, DR*, FPU state, individual flag bits) that no caller wants.
     * {@code limit} caps the list (used for example lists in error messages).
     */
    private static List<String> defaultReadRegisterNames(Program program, int limit) {
        List<String> names = curatedGpRegisterNames(program);
        if (names == null) {
            List<Register> regs = new ArrayList<>();
            for (Register r : program.getLanguage().getRegisters()) {
                if (!r.isBaseRegister()) {
                    continue;
                }
                int flags = r.getTypeFlags();
                if ((flags & (Register.TYPE_HIDDEN | Register.TYPE_CONTEXT
                        | Register.TYPE_FP | Register.TYPE_VECTOR)) != 0) {
                    continue;
                }
                regs.add(r);
            }
            Collections.sort(regs);
            names = new ArrayList<>();
            for (Register r : regs) {
                names.add(r.getName());
            }
        }
        return names.subList(0, Math.min(limit, names.size()));
    }

    /**
     * Curated GP register names for known processor families, or {@code null}
     * when the processor is unlisted (or the language variant has none of the
     * curated names) so the caller falls back to the generic filter. Names
     * that do not exist in the language variant (e.g. R8 on 32-bit x86) are
     * dropped.
     */
    private static List<String> curatedGpRegisterNames(Program program) {
        List<String> wanted;
        switch (program.getLanguage().getProcessor().toString()) {
            case "x86":
                wanted = program.getDefaultPointerSize() > 4
                        ? List.of("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
                                "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                                "RIP", "RFLAGS")
                        : List.of("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
                                "EIP", "EFLAGS");
                break;
            case "AARCH64":
                List<String> aarch64 = new ArrayList<>();
                for (int i = 0; i <= 30; i++) {
                    aarch64.add("X" + i);
                }
                aarch64.add("SP");
                aarch64.add("PC");
                wanted = aarch64;
                break;
            case "ARM":
                wanted = List.of("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
                        "r9", "r10", "r11", "r12", "sp", "lr", "pc", "CPSR");
                break;
            case "MIPS":
                wanted = List.of("v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2",
                        "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5",
                        "s6", "s7", "t8", "t9", "gp", "sp", "fp", "ra");
                break;
            case "PowerPC":
                List<String> ppc = new ArrayList<>();
                for (int i = 0; i <= 31; i++) {
                    ppc.add("r" + i);
                }
                ppc.add("lr");
                ppc.add("ctr");
                ppc.add("cr");
                wanted = ppc;
                break;
            default:
                return null;
        }
        List<String> existing = new ArrayList<>();
        for (String name : wanted) {
            if (program.getRegister(name) != null) {
                existing.add(name);
            }
        }
        return existing.isEmpty() ? null : existing;
    }

    /** Encode a pointer-sized value in the program's endianness. */
    private static byte[] pointerBytes(long value, int size, boolean bigEndian) {
        byte[] out = new byte[size];
        for (int i = 0; i < size; i++) {
            int shift = bigEndian ? (size - 1 - i) * 8 : i * 8;
            out[i] = (byte) ((value >> shift) & 0xFF);
        }
        return out;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16));
            hex.append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }

    /** Best-effort ASCII rendering: printable bytes as-is, everything else '.'. */
    private static String toAscii(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length);
        for (byte b : bytes) {
            int c = b & 0xFF;
            sb.append(c >= 0x20 && c <= 0x7E ? (char) c : '.');
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replace(" ", "").replace("0x", "");
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
