package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for control-flow graph export: the real basic-block graph of a
 * function, so agents do not have to reconstruct control flow from disassembly
 * text.
 *
 * <p>Built on {@link BasicBlockModel}, Ghidra's program-model block API, which
 * is headless-safe and read-only. Nodes are basic blocks; edges are the
 * intra-function flows between them, classified from each
 * {@link CodeBlockReference}'s {@link FlowType}.
 */
@McpToolGroup(value = "analysis", description = "Completeness analysis, control flow, similarity, crypto detection, memory inspection")
public class CfgService {

    private static final int MAX_NODES_LIMIT = 50000;

    private final ProgramProvider programProvider;

    public CfgService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/get_function_cfg",
             description = "Export a function's control-flow graph: basic blocks (nodes) and the flows between "
                         + "them (edges), from Ghidra's BasicBlockModel. Use it for path analysis (\"is there a "
                         + "path from A to B\"), finding loop bodies (back edges point from a node to an "
                         + "earlier-addressed node), spotting switch dispatch (one node with many jump out-edges), "
                         + "then drill into a block's code with disassemble_function / decompile or "
                         + "include_instructions=true. Nodes carry id (0-based, stable within this response), "
                         + "start/end address, length_bytes, instruction_count, is_entry, is_exit (no "
                         + "intra-function out-edges: returns, noreturn calls, tail jumps away). Edges reference "
                         + "node ids; type is derived from the block exit's FlowType: fallthrough, jump, "
                         + "conditional-jump, indirect-jump (computed target — the switch-dispatch shape), or call. "
                         + "Edges cover intra-function flow only; ordinary calls stay inside the calling block "
                         + "and appear in its instructions, not as edges. Node output is capped at max_nodes "
                         + "(default 2000); when hit, truncated=true and the graph is partial — raise max_nodes "
                         + "or analyze a sub-range. Requires an analyzed function body; on a fresh headless "
                         + "import run reanalyze first or the body may be undefined.",
             category = "analysis")
    public Response getFunctionCfg(
            @Param(value = "function",
                   description = "Function name or entry-point address (0x<hex> or <space>:<hex>, e.g. mem:1000; "
                               + "an address inside the body also resolves). Use list_methods or "
                               + "search_functions_enhanced to find candidates.") String functionRef,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName,
            @Param(value = "include_instructions", defaultValue = "false",
                   description = "true: each node also carries its disassembly lines (address: text). "
                               + "false (default): graph shape only — much smaller responses.") boolean includeInstructions,
            @Param(value = "max_nodes", defaultValue = "2000",
                   description = "Stop adding nodes after this many basic blocks (1-50000, default 2000). "
                               + "truncated=true in the response means the cap was hit and the graph is partial; "
                               + "edges to nodes beyond the cap are dropped.") int maxNodes) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionRef == null || functionRef.isBlank()) {
            return Response.err("function is required (name or address). Use list_methods or "
                    + "search_functions_enhanced to find candidates.");
        }
        if (maxNodes < 1 || maxNodes > MAX_NODES_LIMIT) {
            return Response.err("max_nodes must be between 1 and " + MAX_NODES_LIMIT);
        }

        try {
            FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionRef, "").tryResolve(program);
            if (!resolved.isSuccess()) {
                return Response.err("Function not found: '" + functionRef + "'. Use list_methods or "
                        + "search_functions_enhanced to find candidates.");
            }
            Function func = resolved.function();

            if (func.getBody() == null || func.getBody().isEmpty()) {
                return Response.err("Function '" + func.getName() + "' has an undefined or empty body "
                        + "(no analyzed code). Run reanalyze first, or check the function with "
                        + "disassemble_function.");
            }

            BasicBlockModel blockModel = new BasicBlockModel(program);
            Listing listing = program.getListing();
            Address entryPoint = func.getEntryPoint();

            // Collect nodes up to the cap; keep iterating afterwards (cheap) so
            // total_nodes is exact even when the response is truncated.
            List<CodeBlock> kept = new ArrayList<>();
            Map<String, Integer> idByStart = new HashMap<>();
            int totalNodes = 0;
            CodeBlockIterator blockIter =
                    blockModel.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                if (totalNodes < maxNodes) {
                    idByStart.put(block.getFirstStartAddress().toString(), kept.size());
                    kept.add(block);
                }
                totalNodes++;
            }
            boolean truncated = totalNodes > kept.size();

            List<Map<String, Object>> nodes = new ArrayList<>();
            List<Map<String, Object>> edges = new ArrayList<>();
            for (int id = 0; id < kept.size(); id++) {
                CodeBlock block = kept.get(id);
                Map<String, Object> node = new LinkedHashMap<>();
                node.put("id", id);
                node.put("start_address", block.getFirstStartAddress().toString(false));
                node.put("end_address", block.getMaxAddress().toString(false));
                node.put("length_bytes", block.getNumAddresses());
                int instructionCount = 0;
                List<String> lines = includeInstructions ? new ArrayList<>() : null;
                InstructionIterator instrIter = listing.getInstructions(block, true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    instructionCount++;
                    if (lines != null) {
                        lines.add(instr.getAddress().toString(false) + ": " + instr.toString());
                    }
                }
                node.put("instruction_count", instructionCount);
                node.put("is_entry", block.contains(entryPoint));
                if (lines != null) {
                    node.put("instructions", lines);
                }

                int outEdges = 0;
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    Address destAddr = ref.getDestinationAddress();
                    if (destAddr == null) {
                        continue;
                    }
                    Integer toId = idByStart.get(destAddr.toString());
                    if (toId == null) {
                        // Flow leaves the function body (tail call/jump away, or
                        // a node beyond the max_nodes cap): not part of the
                        // intra-function graph.
                        continue;
                    }
                    Map<String, Object> edge = new LinkedHashMap<>();
                    edge.put("from", id);
                    edge.put("to", toId);
                    edge.put("type", classifyFlow(ref.getFlowType()));
                    edges.add(edge);
                    outEdges++;
                }
                node.put("is_exit", outEdges == 0);
                nodes.add(node);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function", func.getName());
            result.putAll(ServiceUtils.addressToJson(entryPoint, program));
            result.put("nodes", nodes);
            result.put("edges", edges);
            result.put("node_count", nodes.size());
            result.put("edge_count", edges.size());
            result.put("total_nodes", totalNodes);
            result.put("truncated", truncated);
            result.put("max_nodes", maxNodes);
            result.put("include_instructions", includeInstructions);
            return Response.ok(result);
        } catch (Exception e) {
            Msg.error(this, "get_function_cfg failed", e);
            return Response.err("get_function_cfg failed: " + e.getMessage());
        }
    }

    /**
     * Classify a block-to-block flow for the edge {@code type} vocabulary.
     * Calls first (a computed call is still a call, never a jump); conditional
     * jumps before plain jumps; computed unconditional jumps are the indirect
     * (switch-dispatch) shape; anything with fall-through semantics that is
     * neither call nor jump is a fall-through edge. Exotic leftovers keep
     * Ghidra's own flow-type name, lowercased.
     */
    static String classifyFlow(FlowType ft) {
        if (ft == null) {
            return "unknown";
        }
        if (ft.isCall()) {
            return "call";
        }
        if (ft.isJump()) {
            if (ft.isConditional()) {
                return "conditional-jump";
            }
            return ft.isComputed() ? "indirect-jump" : "jump";
        }
        if (ft.hasFallthrough()) {
            return "fallthrough";
        }
        return ft.getName().toLowerCase();
    }
}
