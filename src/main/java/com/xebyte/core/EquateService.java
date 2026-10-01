package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for equate CRUD: Ghidra's name-to-scalar-value tables. An equate
 * names a magic constant (MMIO register bit field, errno code, syscall
 * number, RTOS constant); attaching it to an instruction operand makes the
 * disassembly and decompiler render the name instead of the raw number.
 *
 * <p>Built on {@link EquateTable} / {@link Equate}. Values are signed 64-bit;
 * accepted as {@code 0x<hex>} or decimal in, reported in both forms out.
 */
@McpToolGroup(value = "symbol", description = "Create/rename/delete labels, rename data, globals, external locations, equates")
public class EquateService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public EquateService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // list_equates
    // -----------------------------------------------------------------------

    @McpTool(path = "/list_equates",
             description = "List the program's equate table — named scalar constants (MMIO bit fields, errno "
                         + "codes, syscall numbers, RTOS constants). Each entry reports name, value as signed "
                         + "decimal and hex, and reference_count (how many instruction operands render the name "
                         + "instead of the number). Filter to one constant with value (e.g. find what 0x3c is "
                         + "named). Create new ones with create_equate.",
             category = "symbol")
    public Response listEquates(
            @Param(value = "value", defaultValue = "",
                   description = "Optional value filter: only equates with this scalar value. 0x<hex> or "
                               + "decimal.") String valueFilter,
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of equates to skip before this page starts; 0 begins at the "
                               + "first.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Maximum equates returned in this page (default 100). Pass 0 or a negative "
                               + "value for no limit; `total` in the response always reports the full "
                               + "count.") int limit,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Long filter = null;
        if (valueFilter != null && !valueFilter.isBlank()) {
            filter = parseScalar(valueFilter);
            if (filter == null) {
                return Response.err("Invalid value '" + valueFilter + "': expected 0x<hex> or decimal "
                        + "within signed 64-bit range.");
            }
        }

        try {
            EquateTable equateTable = program.getEquateTable();
            List<Map<String, Object>> equates = new ArrayList<>();
            Iterator<Equate> iter = equateTable.getEquates();
            while (iter.hasNext()) {
                Equate equate = iter.next();
                if (filter != null && equate.getValue() != filter) {
                    continue;
                }
                equates.add(equateToJson(equate));
            }
            equates.sort(Comparator.comparing(e -> (String) e.get("name")));
            return ServiceUtils.paged("equates", equates, offset, limit);
        } catch (Exception e) {
            Msg.error(this, "list_equates failed", e);
            return Response.err("list_equates failed: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // create_equate
    // -----------------------------------------------------------------------

    @McpTool(path = "/create_equate", method = "POST",
             description = "Create an equate: a name for a scalar constant (MMIO register bit field, errno code, "
                         + "syscall number, RTOS constant). With only name+value the equate just enters the "
                         + "table; also pass address + operand_index to attach it to an instruction operand in "
                         + "the same call, which makes the disassembly and decompiler render the name instead "
                         + "of the number (e.g. MOV EAX,0x3c becomes MOV EAX,EXIT_CODE_60). Convention is "
                         + "UPPER_SNAKE_CASE names. Names must be unique per program: a duplicate name is an "
                         + "error reporting the existing equate — inspect with list_equates, replace with "
                         + "remove_equate(delete=true) first. NOTE: the Ghidra GUI listing renders the "
                         + "equate name, but disassemble_function's plain text is Ghidra's default operand "
                         + "form and does NOT substitute equates — confirm an attach with list_equates "
                         + "(reference_count), not by re-reading the disassembly.",
             category = "symbol")
    public Response createEquate(
            @Param(value = "name", source = ParamSource.BODY,
                   description = "Equate name (UPPER_SNAKE_CASE by convention, e.g. UART_SR_RXNE, "
                               + "SYS_exit_group). Must be unique in the program.") String name,
            @Param(value = "value", source = ParamSource.BODY,
                   description = "Scalar value the name stands for: 0x<hex> or decimal, signed 64-bit range "
                               + "(e.g. 0x3c, 60, -1, 0x80000000).") String valueStr,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                   description = "Optional instruction address to attach the equate to immediately. 0x<hex> "
                               + "or <space>:<hex> (e.g., mem:1000, code:ff00). Note: some programs — "
                               + "particularly embedded/microcontroller targets — are not "
                               + "address-space-agnostic; use get_address_spaces to discover spaces before "
                               + "assuming a plain hex address is unambiguous. Requires operand_index; the "
                               + "address must hold a defined instruction (run reanalyze first on a fresh "
                               + "headless import).") String addressStr,
            @Param(value = "operand_index", source = ParamSource.BODY, defaultValue = "-1",
                   description = "Operand of the instruction at address to attach to (0-based; required when "
                               + "address is given). For MOV EAX,0x3c the immediate is operand 1. A warning "
                               + "is returned if the operand's constant does not equal value — the equate "
                               + "still attaches but renders as the wrong name there.") int operandIndex,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isBlank()) {
            return Response.err("name is required");
        }
        name = name.trim();
        if (valueStr == null || valueStr.isBlank()) {
            return Response.err("value is required (0x<hex> or decimal)");
        }
        Long value = parseScalar(valueStr);
        if (value == null) {
            return Response.err("Invalid value '" + valueStr + "': expected 0x<hex> or decimal "
                    + "within signed 64-bit range.");
        }

        EquateTable equateTable = program.getEquateTable();
        Equate existing = equateTable.getEquate(name);
        if (existing != null) {
            return Response.err("Equate '" + name + "' already exists with value "
                    + formatHex(existing.getValue()) + " (" + existing.getValue() + "). Equate names are "
                    + "unique per program; inspect it with list_equates, or remove_equate(delete=true) "
                    + "first if you mean to replace it.");
        }

        // Validate the attach target before entering the write lambda: address
        // parsing uses a ThreadLocal error channel that does not cross threads.
        boolean attach = addressStr != null && !addressStr.isBlank();
        Address address = null;
        Long operandScalar = null;
        if (attach) {
            if (operandIndex < 0) {
                return Response.err("operand_index is required when address is given (0-based operand of "
                        + "the instruction to attach to).");
            }
            address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }
            Instruction instr = program.getListing().getInstructionAt(address);
            if (instr == null) {
                return Response.err("No defined instruction at " + addressStr + ". Disassemble it first, "
                        + "or run reanalyze on a fresh headless import (import alone leaves function "
                        + "bodies undefined).");
            }
            if (operandIndex >= instr.getNumOperands()) {
                return Response.err("operand_index " + operandIndex + " out of range: instruction at "
                        + addressStr + " (" + instr + ") has " + instr.getNumOperands() + " operand(s).");
            }
            Scalar scalar = instr.getScalar(operandIndex);
            if (scalar != null) {
                operandScalar = scalar.getSignedValue();
            }
        }

        try {
            final String finalName = name;
            final Address finalAddress = address;
            final Long finalOperandScalar = operandScalar;
            final long finalValue = value;
            return threadingStrategy.executeWrite(program, "Create Equate", () -> {
                Equate equate = equateTable.createEquate(finalName, finalValue);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("name", equate.getName());
                result.put("value", equate.getValue());
                result.put("value_hex", formatHex(equate.getValue()));
                result.put("attached", attach);
                if (attach) {
                    equate.addReference(finalAddress, operandIndex);
                    result.put("address", finalAddress.toString(false));
                    result.put("operand_index", operandIndex);
                    if (finalOperandScalar == null) {
                        result.put("warnings", List.of("Operand " + operandIndex + " at "
                                + finalAddress.toString(false) + " has no scalar constant; the equate "
                                + "may not render there."));
                    } else if (finalOperandScalar != finalValue) {
                        result.put("warnings", List.of("Operand " + operandIndex + " at "
                                + finalAddress.toString(false) + " holds constant "
                                + formatHex(finalOperandScalar) + " but equate value is "
                                + formatHex(finalValue) + " — the listing will render the name for a "
                                + "different number than the operand actually uses."));
                    }
                }
                result.put("reference_count", equate.getReferenceCount());
                return Response.ok(result);
            });
        } catch (Exception e) {
            Msg.error(this, "create_equate failed", e);
            return Response.err("create_equate failed: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // remove_equate
    // -----------------------------------------------------------------------

    @McpTool(path = "/remove_equate", method = "POST",
             description = "Remove an equate reference or delete a whole equate. Default mode detaches ONE "
                         + "reference: name + address + operand_index — the operand goes back to rendering "
                         + "the raw number and the equate stays in the table (with one fewer reference). "
                         + "delete=true instead removes the equate entirely: every reference in the program "
                         + "is detached and the name is forgotten. Both modes are transaction-wrapped and "
                         + "undoable. Use list_equates to find names and reference counts.",
             category = "symbol")
    public Response removeEquate(
            @Param(value = "name", source = ParamSource.BODY,
                   description = "Equate name (from list_equates).") String name,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                   description = "Detach mode: instruction address whose operand reference is removed. "
                               + "0x<hex> or <space>:<hex>. Required unless delete=true.") String addressStr,
            @Param(value = "operand_index", source = ParamSource.BODY, defaultValue = "-1",
                   description = "Detach mode: 0-based operand index of the reference to remove. Required "
                               + "unless delete=true.") int operandIndex,
            @Param(value = "delete", source = ParamSource.BODY, defaultValue = "false",
                   description = "true: delete the whole equate and detach all its references; address and "
                               + "operand_index are ignored. false (default): detach one reference "
                               + "(address + operand_index).") boolean delete,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isBlank()) {
            return Response.err("name is required (from list_equates)");
        }
        name = name.trim();

        EquateTable equateTable = program.getEquateTable();
        Equate equate = equateTable.getEquate(name);
        if (equate == null) {
            return Response.err("Equate not found: '" + name + "'. Use list_equates to see the table.");
        }

        if (delete) {
            final String finalName = name;
            final int refsBefore = equate.getReferenceCount();
            try {
                return threadingStrategy.executeWrite(program, "Delete Equate", () -> {
                    boolean removed = equateTable.removeEquate(finalName);
                    if (!removed) {
                        return Response.err("Failed to delete equate '" + finalName + "'.");
                    }
                    Map<String, Object> result = new LinkedHashMap<>();
                    result.put("status", "success");
                    result.put("deleted", true);
                    result.put("name", finalName);
                    result.put("references_removed", refsBefore);
                    return Response.ok(result);
                });
            } catch (Exception e) {
                Msg.error(this, "remove_equate(delete) failed", e);
                return Response.err("remove_equate failed: " + e.getMessage());
            }
        }

        // Detach-one-reference mode.
        if (addressStr == null || addressStr.isBlank()) {
            return Response.err("address is required in detach mode (or pass delete=true to remove the "
                    + "whole equate).");
        }
        if (operandIndex < 0) {
            return Response.err("operand_index is required in detach mode (0-based operand of the "
                    + "instruction at address).");
        }
        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        boolean hasRef = false;
        for (EquateReference ref : equate.getReferences()) {
            if (ref.getAddress().equals(address) && ref.getOpIndex() == operandIndex) {
                hasRef = true;
                break;
            }
        }
        if (!hasRef) {
            List<String> currentRefs = new ArrayList<>();
            for (EquateReference ref : equate.getReferences()) {
                currentRefs.add(ref.getAddress().toString(false) + ":" + ref.getOpIndex());
                if (currentRefs.size() >= 10) {
                    break;
                }
            }
            return Response.err("Equate '" + name + "' has no reference at " + addressStr
                    + " operand " + operandIndex + ". Current references (address:operand_index): "
                    + (currentRefs.isEmpty() ? "none" : String.join(", ", currentRefs)));
        }

        final Address finalAddress = address;
        final String finalName = name;
        try {
            return threadingStrategy.executeWrite(program, "Remove Equate Reference", () -> {
                equate.removeReference(finalAddress, operandIndex);
                int remaining = equate.getReferenceCount();
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("deleted", false);
                result.put("name", finalName);
                result.put("address", finalAddress.toString(false));
                result.put("operand_index", operandIndex);
                result.put("reference_count", remaining);
                if (remaining == 0) {
                    result.put("message", "Detached the last reference; the equate remains in the table "
                            + "with 0 references. Call again with delete=true to remove it entirely.");
                }
                return Response.ok(result);
            });
        } catch (Exception e) {
            Msg.error(this, "remove_equate(detach) failed", e);
            return Response.err("remove_equate failed: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static Map<String, Object> equateToJson(Equate equate) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("name", equate.getName());
        entry.put("value", equate.getValue());
        entry.put("value_hex", formatHex(equate.getValue()));
        entry.put("reference_count", equate.getReferenceCount());
        return entry;
    }

    /**
     * Parse a scalar as {@code 0x<hex>} (optionally negative) or decimal.
     * Returns {@code null} on any malformed or out-of-range input. Deliberately
     * not {@code Long.decode}: its octal and {@code #} forms would surprise
     * callers.
     */
    static Long parseScalar(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        boolean negative = t.startsWith("-");
        String body = negative ? t.substring(1) : t;
        try {
            long magnitude;
            if (body.length() > 2 && body.charAt(0) == '0'
                    && (body.charAt(1) == 'x' || body.charAt(1) == 'X')) {
                magnitude = Long.parseLong(body.substring(2), 16);
            } else {
                magnitude = Long.parseLong(body, 10);
            }
            return negative ? -magnitude : magnitude;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Hex rendering that keeps negative values readable: -1 -> "-0x1". */
    static String formatHex(long v) {
        if (v >= 0) {
            return "0x" + Long.toHexString(v);
        }
        if (v == Long.MIN_VALUE) {
            return "-0x8000000000000000";
        }
        return "-0x" + Long.toHexString(-v);
    }
}
