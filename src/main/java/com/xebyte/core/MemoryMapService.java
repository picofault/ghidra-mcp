package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service for the firmware memory map: a one-shot structured view of every
 * memory block and address space (including overlays), programmatic overlay
 * region creation for bank-switching / ROM-shadowing analysis, and CMSIS-SVD
 * import that materializes peripheral register structures so the decompiler
 * shows {@code GPIOA->ODR} instead of {@code *(uint *)0x40020014}.
 */
@McpToolGroup(value = "memorymap", description = "Memory map / MMIO: structured block+space dump, overlay regions, CMSIS-SVD peripheral import")
public class MemoryMapService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public MemoryMapService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // get_memory_map
    // -----------------------------------------------------------------------

    @McpTool(path = "/get_memory_map", method = "GET",
             description = "One-shot structured dump of the program's memory map: every memory block (name, "
                         + "start/end/size, rwx permissions, volatile flag, source, initialized/uninitialized/"
                         + "overlay, block type, comment) plus every address space with its type and — for "
                         + "overlay spaces — the base space it overlays. This is the \"what does my firmware's "
                         + "memory look like\" tool for bare-metal targets: use it to find flash/RAM/peripheral "
                         + "regions before choosing analysis ranges, and to see overlay views created by "
                         + "create_overlay_region or create_memory_block(overlay=true). list_segments reports "
                         + "the same blocks in a flatter form; get_address_spaces reports spaces only.",
             category = "memorymap")
    public Response getMemoryMap(
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            return threadingStrategy.executeRead(() -> {
                Memory memory = program.getMemory();
                List<Map<String, Object>> blocks = new ArrayList<>();
                for (MemoryBlock block : memory.getBlocks()) {
                    blocks.add(blockToJson(block));
                }

                List<Map<String, Object>> spaces = new ArrayList<>();
                int overlayCount = 0;
                for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
                    Map<String, Object> s = JsonHelper.mapOf(
                        "name", space.getName(),
                        "type", spaceTypeName(space.getType()),
                        "is_overlay", space.isOverlaySpace(),
                        "size", space.getSize());
                    if (space.isOverlaySpace()) {
                        overlayCount++;
                        if (space instanceof OverlayAddressSpace overlay) {
                            s.put("overlayed_space", overlay.getOverlayedSpace().getName());
                        }
                    }
                    spaces.add(s);
                }

                Map<String, Object> out = new LinkedHashMap<>();
                out.put("blocks", blocks);
                out.put("address_spaces", spaces);
                out.put("block_count", blocks.size());
                out.put("address_space_count", spaces.size());
                out.put("overlay_space_count", overlayCount);
                return Response.ok(out);
            });
        } catch (Exception e) {
            Msg.error(this, "get_memory_map failed", e);
            return Response.err("get_memory_map failed: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // create_overlay_region
    // -----------------------------------------------------------------------

    @McpTool(path = "/create_overlay_region", method = "POST",
             description = "Create an overlay address space over an existing initialized region — the Ghidra "
                         + "model for bank switching / ROM shadowing (e.g., a flash bank visible at 0x08000000 "
                         + "depending on a config register). The new block SHARES the bytes of the source "
                         + "region (byte-mapped, 1:1): reading overlay space addresses reads through to the "
                         + "underlying memory, and nothing is copied. The response reports the generated "
                         + "overlay space name; read the overlay view with read_memory using "
                         + "<overlay_space>:<hex> addresses, and see it in get_memory_map. The source range "
                         + "must be inside one initialized block. To create a plain (non-overlapping) block "
                         + "or an overlay with its own copied bytes, use create_memory_block instead.",
             category = "memorymap")
    public Response createOverlayRegion(
            @Param(value = "name", source = ParamSource.BODY,
                   description = "Name for the overlay address space and its block, e.g. FLASH_BANK1. "
                               + "The space name is what get_address_spaces / get_memory_map report and the "
                               + "prefix addresses must use to read the overlay (e.g. \"FLASH_BANK1:08000000\"). "
                               + "Required and unique among spaces.") String name,
            @Param(value = "overlay_address", paramType = "address", source = ParamSource.BODY,
                   description = "Start address of the block INSIDE the new overlay space. Accepts 0x<hex> "
                               + "(offsets are the same numeric range as the base space) or <space>:<hex>. "
                               + "Note: embedded/microcontroller targets are not address-space-agnostic; use "
                               + "get_address_spaces first. Required.") String overlayAddressStr,
            @Param(value = "source_address", paramType = "address", source = ParamSource.BODY,
                   description = "Start of the existing initialized region whose bytes the overlay maps "
                               + "through to. The range [source_address, source_address+length) must lie "
                               + "inside one initialized memory block. Accepts 0x<hex> or <space>:<hex>. "
                               + "Required.") String sourceAddressStr,
            @Param(value = "length", source = ParamSource.BODY,
                   description = "Length in bytes of the mapped region. Must be positive and fit within the "
                               + "source block. Required.") long length,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isBlank()) {
            return Response.err("name parameter required");
        }
        if (length <= 0) {
            return Response.err("length must be positive (got " + length + ")");
        }

        // Both address parses must happen on the HTTP worker thread BEFORE the
        // write lambda — parse errors are a ThreadLocal invisible on the EDT.
        Address overlayAddr = ServiceUtils.parseAddress(program, overlayAddressStr);
        if (overlayAddr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }
        Address sourceAddr = ServiceUtils.parseAddress(program, sourceAddressStr);
        if (sourceAddr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        try {
            Response result = threadingStrategy.executeWrite(program, "Create overlay region", () -> {
                Memory memory = program.getMemory();

                Address sourceEnd;
                try {
                    sourceEnd = sourceAddr.add(length - 1);
                } catch (Exception e) {
                    return Response.err("source range overflows the address space");
                }
                MemoryBlock sourceBlock = memory.getBlock(sourceAddr);
                if (sourceBlock == null) {
                    return Response.err("No memory block contains source_address " + sourceAddressStr
                            + ". Check the range against get_memory_map.");
                }
                if (!sourceBlock.isInitialized()) {
                    return Response.err("Source block '" + sourceBlock.getName() + "' is uninitialized — "
                            + "an overlay maps real bytes. Pick a source inside an initialized region "
                            + "(see get_memory_map).");
                }
                if (!sourceBlock.contains(sourceEnd)) {
                    return Response.err("Mapped range of " + length + " bytes crosses the end of block '"
                            + sourceBlock.getName() + "' (ends at " + sourceBlock.getEnd()
                            + "). Shorten length.");
                }

                // 1:1 byte mapping: overlay address X reads the byte at
                // source_start + (X - overlay_start). This is Ghidra's model
                // for banked memory views — no storage, shared bytes.
                ghidra.program.database.mem.ByteMappingScheme scheme =
                        new ghidra.program.database.mem.ByteMappingScheme(1, 1);
                MemoryBlock block = memory.createByteMappedBlock(
                        name, overlayAddr, sourceAddr, length, scheme, true);
                block.setRead(true);
                block.setWrite(false);
                block.setExecute(sourceBlock.isExecute());
                block.setVolatile(sourceBlock.isVolatile());

                return Response.ok(JsonHelper.mapOf(
                    "status", "success",
                    "name", name,
                    "overlay_space", block.getStart().getAddressSpace().getName(),
                    "block_start", block.getStart().toString(),
                    "block_end", block.getEnd().toString(),
                    "size", block.getSize(),
                    "mapped_from", sourceAddr.toString(false),
                    "mapped_to_end", sourceEnd.toString(false),
                    "source_block", sourceBlock.getName(),
                    "address_full", block.getStart().toString(),
                    "message", "Overlay space '" + block.getStart().getAddressSpace().getName()
                            + "' created over [" + sourceAddr + " .. " + sourceEnd
                            + "]. Read it with <overlay_space>:<hex> addresses."));
            });
            return result;
        } catch (Exception e) {
            Msg.error(this, "create_overlay_region failed", e);
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            if (msg != null && msg.contains("Duplicate")) {
                return Response.err("Overlay space or block name '" + name + "' already exists. "
                        + "Check get_memory_map and pick a new name.");
            }
            return Response.err("create_overlay_region failed: " + msg);
        }
    }

    // -----------------------------------------------------------------------
    // import_svd
    // -----------------------------------------------------------------------

    @McpTool(path = "/import_svd", method = "POST",
             description = "Import a CMSIS-SVD device description (the vendor XML from a device pack) and "
                         + "materialize it for bare-metal firmware analysis: one structure type per peripheral "
                         + "with a member per register (offset from addressOffset, width from size), bit-field "
                         + "members for nested <field> definitions where they pack cleanly, one volatile "
                         + "uninitialized memory block per peripheral address range, and a label at each "
                         + "peripheral base address. Feed the vendor SVD from the device pack to label MMIO "
                         + "BEFORE analyzing bare-metal firmware, then peripheral accesses read naturally: "
                         + "cast raw pointers to the generated struct (GPIOA_T *) via apply_data_type / "
                         + "set_function_prototype on initialized regions — the MMIO blocks this endpoint "
                         + "creates are uninitialized, so labels + structs are the ground truth and code "
                         + "referencing 0x40020014 is annotated by applying the type at the reference site. "
                         + "Pass the XML inline (svd_content) or as a server-side file path (svd_path). The "
                         + "common CMSIS-SVD subset is handled: device/peripherals/registers/fields; "
                         + "peripheral-level derivedFrom references are resolved (registers inherited from "
                         + "the referenced peripheral, chains followed, cycles/missing targets reported in "
                         + "skipped); register-level <dim> arrays are expanded into one register per "
                         + "index (dimIndex ranges/lists honored); <cluster> elements are flattened into "
                         + "plain registers (offsets accumulated, names prefixed, nesting supported); "
                         + "other exotic attributes are skipped gracefully and reported in "
                         + "skipped/skipped_details. Re-importing overwrites struct definitions "
                         + "by name but does not delete blocks it did not create.",
             category = "memorymap")
    public Response importSvd(
            @Param(value = "svd_content", source = ParamSource.BODY, defaultValue = "",
                   description = "Full CMSIS-SVD XML document as an inline string. Mutually exclusive with "
                               + "svd_path; exactly one is required.") String svdContent,
            @Param(value = "svd_path", source = ParamSource.BODY, defaultValue = "",
                   description = "Absolute path to a CMSIS-SVD file on the server's filesystem (e.g. an "
                               + "unpacked vendor device pack). Mutually exclusive with svd_content.") String svdPath,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always specify "
                               + "when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        boolean haveContent = svdContent != null && !svdContent.isBlank();
        boolean havePath = svdPath != null && !svdPath.isBlank();
        if (haveContent == havePath) {
            return Response.err("Provide exactly one of svd_content (inline XML string) or svd_path "
                    + "(server-side file path)");
        }

        String xml;
        if (havePath) {
            Path file = Path.of(svdPath);
            if (!Files.isRegularFile(file)) {
                return Response.err("svd_path does not exist on the server: " + svdPath);
            }
            try {
                xml = Files.readString(file);
            } catch (Exception e) {
                return Response.err("Failed to read svd_path: " + e.getMessage());
            }
        } else {
            xml = svdContent;
        }

        SvdModel model;
        try {
            model = parseSvd(xml);
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "import_svd parse failure", e);
            return Response.err("Failed to parse SVD XML: " + e.getMessage());
        }
        if (model.peripherals.isEmpty()) {
            return Response.err("SVD parsed but contains no <peripheral> elements under <peripherals>");
        }

        final SvdModel importModel = model;
        try {
            return threadingStrategy.executeWrite(program, "Import CMSIS-SVD",
                () -> applySvd(program, importModel));
        } catch (Exception e) {
            Msg.error(this, "import_svd failed", e);
            return Response.err("import_svd failed: " + (e.getMessage() != null ? e.getMessage() : e));
        }
    }

    // -----------------------------------------------------------------------
    // SVD model + parsing
    // -----------------------------------------------------------------------

    /**
     * One SVD &lt;field&gt; inside a register: bit position and width.
     * {@code derivedFrom} is the field-level reference attribute: when set,
     * the field inherits the same register's referenced field's bit position
     * and/or width (resolved within the register by
     * {@link #resolveDerivedFields}); any explicitly-present bit position
     * child overrides the inherited one; {@code null} once resolved. During
     * parsing a lsb of -1 means "no parseable bit position — inherit" and a
     * width of 0 means "no explicit &lt;bitWidth&gt; — inherit".
     */
    record SvdField(String name, int lsb, int width, String derivedFrom) {}

    /**
     * One SVD &lt;register&gt; (or &lt;register&gt; inside a cluster,
     * flattened). {@code derivedFrom} is the register-level reference
     * attribute: when set, the register inherits the same peripheral's
     * referenced register's size and fields (resolved within the peripheral
     * by {@link #resolveDerivedRegisters}); {@code null} once resolved.
     * During parsing a size of 0 means "no explicit &lt;size&gt; — inherit"
     * and a null {@code fields} means "no explicit &lt;fields&gt; — inherit".
     */
    record SvdRegister(String name, long offset, int size, List<SvdField> fields,
                       List<String> skippedFields, String derivedFrom) {}

    /**
     * One SVD &lt;peripheral&gt; with its flattened register list.
     * {@code derivedFrom} is the peripheral-level reference attribute: when
     * set, the peripheral inherits the referenced peripheral's registers
     * (resolved after the full parse by {@link #resolveDerivedPeripherals}).
     */
    record SvdPeripheral(String name, long baseAddress, String derivedFrom,
                         List<SvdRegister> registers, List<String> skipped) {}

    /** Whole parsed device. */
    record SvdModel(String deviceName, List<SvdPeripheral> peripherals) {}

    /**
     * Parse the common CMSIS-SVD subset with JDK built-ins only. Expands
     * register-level &lt;dim&gt; arrays into one register per index, flattens
     * &lt;cluster&gt; elements into plain registers (offsets accumulated down
     * the nesting chain, names prefixed outermost-first) and skips any
     * register or cluster whose addressOffset/size cannot be understood
     * (reported back to the caller). Peripheral-level derivedFrom references
     * are resolved after the full parse; see {@link #resolveDerivedPeripherals}.
     */
    static SvdModel parseSvd(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Hardened parser: no DTDs, no external entities — SVD files are
        // untrusted input that can arrive from arbitrary vendor packs.
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
        Element root = doc.getDocumentElement();
        if (root == null || !"device".equals(root.getTagName())) {
            throw new IllegalArgumentException("Not a CMSIS-SVD file: root element is '"
                    + (root == null ? "(none)" : root.getTagName()) + "', expected 'device'");
        }

        String deviceName = firstChildText(root, "name", "(unnamed device)");
        List<SvdPeripheral> peripherals = new ArrayList<>();
        Element peripheralsEl = firstChildElement(root, "peripherals");
        if (peripheralsEl == null) {
            return new SvdModel(deviceName, peripherals);
        }
        int deviceSize = (int) parseLongOr(firstChildText(root, "size", ""), 0);

        NodeList periphNodes = peripheralsEl.getElementsByTagName("peripheral");
        for (int i = 0; i < periphNodes.getLength(); i++) {
            Node n = periphNodes.item(i);
            if (!(n instanceof Element el)) {
                continue;
            }
            String name = textOf(firstChildElement(el, "name"));
            List<String> skipped = new ArrayList<>();
            if (name == null || name.isBlank()) {
                continue;
            }
            String derivedFrom = el.getAttribute("derivedFrom");
            if (derivedFrom.isBlank()) {
                derivedFrom = null;
            }
            long base = parseLongOr(textOf(firstChildElement(el, "baseAddress")), -1);
            if (base < 0) {
                skipped.add("peripheral: no parseable <baseAddress>");
                continue;
            }
            List<SvdRegister> registers = new ArrayList<>();
            Element regsEl = firstChildElement(el, "registers");
            if (regsEl != null) {
                NodeList regNodes = regsEl.getChildNodes();
                for (int j = 0; j < regNodes.getLength(); j++) {
                    Node rn = regNodes.item(j);
                    if (!(rn instanceof Element regEl)) {
                        continue;
                    }
                    if ("register".equals(regEl.getTagName())) {
                        if (firstChildElement(regEl, "dim") != null) {
                            List<SvdRegister> expanded =
                                    expandDimRegister(regEl, deviceSize, skipped);
                            if (expanded != null) {
                                registers.addAll(expanded);
                                continue;
                            }
                            // Malformed dim/dimIncrement/dimIndex: fall through
                            // to parseRegister for the usual skip note.
                        }
                        SvdRegister reg = parseRegister(regEl, deviceSize, skipped);
                        if (reg != null) {
                            registers.add(reg);
                        }
                    } else if ("cluster".equals(regEl.getTagName())) {
                        flattenCluster(regEl, deviceSize, registers, skipped, 0, "");
                    }
                }
            }
            // <dim> arrays: expanded into one register per index during the
            // loop above (malformed dim specs fall back to the skip note).
            // Register-level derivedFrom is resolved here, within each
            // peripheral's own final list: inherited registers arriving later
            // via peripheral-level derivation are deep copies, so they behave
            // like any other register in that list.
            registers = resolveDerivedRegisters(registers, skipped, deviceSize);
            peripherals.add(new SvdPeripheral(name, base, derivedFrom, registers, skipped));
        }
        // Resolution runs after the full parse so derivedFrom references to
        // peripherals defined later in the file (forward references) resolve.
        peripherals = resolveDerivedPeripherals(peripherals);
        return new SvdModel(deviceName, peripherals);
    }

    /**
     * Resolve peripheral-level <peripheral derivedFrom="..."> references once
     * every peripheral is parsed. A derived peripheral keeps its own name,
     * baseAddress, and explicitly-declared registers, and inherits the
     * resolved register list of the referenced peripheral (deep-copied, so
     * later mutation of one peripheral's list cannot affect the source);
     * same-named explicit registers override inherited ones. Chains are
     * followed to their ultimate ancestor with cycle protection: on a cycle
     * or a missing target the peripheral keeps its own parsed registers
     * (possibly empty) and a note is added to its skipped list.
     */
    static List<SvdPeripheral> resolveDerivedPeripherals(List<SvdPeripheral> parsed) {
        Map<String, SvdPeripheral> byName = new LinkedHashMap<>();
        for (SvdPeripheral p : parsed) {
            byName.putIfAbsent(p.name(), p);
        }
        List<SvdPeripheral> out = new ArrayList<>(parsed.size());
        for (SvdPeripheral p : parsed) {
            if (p.derivedFrom() == null) {
                out.add(p);
                continue;
            }
            List<String> skipped = new ArrayList<>(p.skipped());
            List<SvdRegister> inherited =
                    resolveInheritedRegisters(p.name(), p.derivedFrom(), byName, skipped);
            List<SvdRegister> effective = inherited != null
                    ? mergeRegisters(inherited, p.registers())
                    : deepCopyRegisters(p.registers());
            out.add(new SvdPeripheral(p.name(), p.baseAddress(), p.derivedFrom(),
                    effective, skipped));
        }
        return out;
    }

    /**
     * Follow a derivedFrom chain to its ultimate ancestor and return the
     * register list inherited from it, folded through any intermediate derived
     * peripherals so each link's own registers override what it inherited.
     * Returns null when the chain is broken — a cycle or a target that does
     * not name a parsed peripheral — with the reason appended to
     * {@code skipped}; the caller then leaves the peripheral its own registers.
     */
    private static List<SvdRegister> resolveInheritedRegisters(String self, String firstRef,
            Map<String, SvdPeripheral> byName, List<String> skipped) {
        Set<String> visited = new HashSet<>();
        visited.add(self);
        List<SvdPeripheral> chain = new ArrayList<>();
        String ref = firstRef;
        while (ref != null) {
            if (!visited.add(ref)) {
                skipped.add("derivedFrom: derivation cycle at '" + ref
                        + "'; kept own registers");
                return null;
            }
            SvdPeripheral target = byName.get(ref);
            if (target == null) {
                skipped.add("derivedFrom: target '" + ref
                        + "' not found among parsed peripherals; kept own registers");
                return null;
            }
            chain.add(target);
            ref = target.derivedFrom();
        }
        List<SvdRegister> effective = null;
        for (int i = chain.size() - 1; i >= 0; i--) {
            effective = mergeRegisters(effective, chain.get(i).registers());
        }
        return effective;
    }

    /**
     * Inherited registers with the explicit ones overlaid by name: an
     * explicitly-declared register replaces the same-named inherited register
     * in place; anything else is appended. Every register in the result is a
     * fresh copy (its field/skipped lists included), so mutating one
     * peripheral's list can never affect another's.
     */
    private static List<SvdRegister> mergeRegisters(List<SvdRegister> inherited,
            List<SvdRegister> explicit) {
        List<SvdRegister> merged = new ArrayList<>();
        if (inherited != null) {
            for (SvdRegister reg : inherited) {
                merged.add(deepCopyRegister(reg));
            }
        }
        if (explicit != null) {
            for (SvdRegister reg : explicit) {
                boolean replaced = false;
                for (int i = 0; i < merged.size(); i++) {
                    if (merged.get(i).name().equals(reg.name())) {
                        merged.set(i, deepCopyRegister(reg));
                        replaced = true;
                        break;
                    }
                }
                if (!replaced) {
                    merged.add(deepCopyRegister(reg));
                }
            }
        }
        return merged;
    }

    private static List<SvdRegister> deepCopyRegisters(List<SvdRegister> regs) {
        List<SvdRegister> copy = new ArrayList<>(regs.size());
        for (SvdRegister reg : regs) {
            copy.add(deepCopyRegister(reg));
        }
        return copy;
    }

    private static SvdRegister deepCopyRegister(SvdRegister reg) {
        // SvdField records are immutable, so sharing them is safe; the
        // register's own identity and lists must be per-peripheral.
        return new SvdRegister(reg.name(), reg.offset(), reg.size(),
                reg.fields() == null ? null : new ArrayList<>(reg.fields()),
                new ArrayList<>(reg.skippedFields()), reg.derivedFrom());
    }

    /**
     * Resolve register-level &lt;register derivedFrom="..."&gt; references
     * within one peripheral's fully-parsed register list. A derived register
     * keeps its own name and offset and inherits the referenced register's
     * size and field list; an explicitly-present &lt;size&gt;/&lt;fields&gt;
     * overrides the inherited one. Chains are followed to the ultimate
     * ancestor with cycle protection: on a cycle or a target that does not
     * name a register of the same peripheral, the register keeps its own
     * parsed values (an unresolved size falls back to the device default and
     * an absent field list stays empty) and a note is added to {@code skipped}.
     */
    private static List<SvdRegister> resolveDerivedRegisters(List<SvdRegister> parsed,
            List<String> skipped, int deviceSize) {
        Map<String, SvdRegister> byName = new LinkedHashMap<>();
        for (SvdRegister reg : parsed) {
            byName.putIfAbsent(reg.name(), reg);
        }
        List<SvdRegister> out = new ArrayList<>(parsed.size());
        for (SvdRegister reg : parsed) {
            if (reg.derivedFrom() == null) {
                out.add(reg);
                continue;
            }
            Set<String> visited = new HashSet<>();
            visited.add(reg.name());
            List<SvdRegister> chain = new ArrayList<>();
            String ref = reg.derivedFrom();
            boolean broken = false;
            while (ref != null) {
                if (!visited.add(ref)) {
                    skipped.add("derivedFrom: derivation cycle at '" + ref
                            + "' for register '" + reg.name() + "'; kept own values");
                    broken = true;
                    break;
                }
                SvdRegister target = byName.get(ref);
                if (target == null) {
                    skipped.add("derivedFrom: target '" + ref
                            + "' not found in peripheral for register '" + reg.name()
                            + "'; kept own values");
                    broken = true;
                    break;
                }
                chain.add(target);
                ref = target.derivedFrom();
            }
            if (broken) {
                out.add(keepOwnRegister(reg, deviceSize));
                continue;
            }
            // Seed with the register's own explicit values, then fold from
            // the ultimate ancestor down: the nearest link carrying an
            // explicit value wins.
            int size = reg.size() > 0 ? reg.size() : 0;
            List<SvdField> fields = reg.fields();
            for (int i = chain.size() - 1; i >= 0; i--) {
                SvdRegister link = chain.get(i);
                if (size == 0 && link.size() > 0) {
                    size = link.size();
                }
                if (fields == null && link.fields() != null) {
                    fields = link.fields();
                }
            }
            if (size == 0) {
                size = deviceSize > 0 ? deviceSize : 32;
            }
            out.add(new SvdRegister(reg.name(), reg.offset(), size,
                    fields == null ? new ArrayList<>() : new ArrayList<>(fields),
                    new ArrayList<>(reg.skippedFields()), null));
        }
        return out;
    }

    /** A register whose derivedFrom chain is broken, back to usable values. */
    private static SvdRegister keepOwnRegister(SvdRegister reg, int deviceSize) {
        int size = reg.size() > 0 ? reg.size() : (deviceSize > 0 ? deviceSize : 32);
        return new SvdRegister(reg.name(), reg.offset(), size,
                reg.fields() == null ? new ArrayList<>() : new ArrayList<>(reg.fields()),
                new ArrayList<>(reg.skippedFields()), null);
    }

    private static SvdRegister parseRegister(Element regEl, int deviceSize, List<String> skipped) {
        return parseRegister(regEl, deviceSize, skipped, false);
    }

    /**
     * Expand one &lt;register&gt; carrying a &lt;dim&gt; declaration into one
     * SvdRegister per index. The register is parsed once via
     * {@link #parseRegister} (with the %s-name skip bypassed), then replicated:
     * the name template's %s is substituted with each index and the offset
     * grows by dimIncrement per position in the index list. Indices come from
     * &lt;dimIndex&gt; ("a-b" range or comma-separated list) and default to
     * 0..dim-1. Returns null when the dim declaration itself is malformed, so
     * the caller falls through to the plain-parse skip note; returns an empty
     * list when the register failed to parse inside parseRegister (notes
     * already recorded there).
     */
    private static List<SvdRegister> expandDimRegister(Element regEl, int deviceSize,
            List<String> skipped) {
        int dim = (int) parseLongOr(textOf(firstChildElement(regEl, "dim")), 0);
        long dimIncrement = parseLongOr(textOf(firstChildElement(regEl, "dimIncrement")), 0);
        String name = textOf(firstChildElement(regEl, "name"));
        if (dim < 1 || dim > 64 || dimIncrement <= 0 || name == null
                || !name.contains("%s")) {
            return null;
        }
        List<Long> indices = new ArrayList<>();
        String dimIndex = textOf(firstChildElement(regEl, "dimIndex"));
        if (dimIndex == null || dimIndex.isBlank()) {
            for (int i = 0; i < dim; i++) {
                indices.add((long) i);
            }
        } else {
            String trimmed = dimIndex.trim();
            int dash = trimmed.indexOf('-');
            if (dash > 0 && !trimmed.contains(",")) {
                long lo = parseLongOr(trimmed.substring(0, dash).trim(), -1);
                long hi = parseLongOr(trimmed.substring(dash + 1).trim(), -1);
                if (lo < 0 || hi < lo) {
                    return null;
                }
                for (long i = lo; i <= hi; i++) {
                    indices.add(i);
                }
            } else {
                for (String token : trimmed.split(",")) {
                    long v = parseLongOr(token.trim(), -1);
                    if (v < 0) {
                        return null;
                    }
                    indices.add(v);
                }
            }
        }
        if (indices.isEmpty() || indices.size() > dim) {
            return null;
        }
        SvdRegister proto = parseRegister(regEl, deviceSize, skipped, true);
        if (proto == null) {
            return new ArrayList<>();
        }
        List<SvdRegister> out = new ArrayList<>(indices.size());
        for (int i = 0; i < indices.size(); i++) {
            String instName = proto.name().replace("%s", Long.toString(indices.get(i)));
            out.add(new SvdRegister(instName, proto.offset() + i * dimIncrement,
                    proto.size(), proto.fields(), proto.skippedFields(), proto.derivedFrom()));
        }
        return out;
    }

    /**
     * Flatten one &lt;cluster&gt; element into plain registers appended to
     * {@code registers}. Nested clusters recurse with the accumulated offset
     * and name prefix, so a register's effective offset is the sum of every
     * ancestor cluster's addressOffset plus its own, and its name is the
     * ancestor cluster names joined with {@code _} (outermost first) plus its
     * own. A cluster carrying &lt;dim&gt; (array-of-clusters) or an
     * unparseable addressOffset is reported in {@code skipped} and skipped
     * whole; registers inside a cluster that themselves carry &lt;dim&gt;
     * fall through to {@link #parseRegister}'s usual dim skip note.
     */
    private static void flattenCluster(Element clusterEl, int deviceSize,
            List<SvdRegister> registers, List<String> skipped, long clusterOffset,
            String prefix) {
        String cname = textOf(firstChildElement(clusterEl, "name"));
        if (cname == null || cname.isBlank()) {
            skipped.add("cluster:? (no <name>)");
            return;
        }
        if (firstChildElement(clusterEl, "dim") != null) {
            skipped.add("cluster:" + safeName(cname) + " (dim cluster arrays unsupported)");
            return;
        }
        long own = parseLongOr(textOf(firstChildElement(clusterEl, "addressOffset")), -1);
        if (own < 0) {
            skipped.add("cluster:" + safeName(cname) + " (no parseable <addressOffset>)");
            return;
        }
        long effective = clusterOffset + own;
        String childPrefix = prefix + safeName(cname) + "_";
        NodeList childNodes = clusterEl.getChildNodes();
        for (int k = 0; k < childNodes.getLength(); k++) {
            Node cn = childNodes.item(k);
            if (!(cn instanceof Element childEl)) {
                continue;
            }
            if ("register".equals(childEl.getTagName())) {
                SvdRegister reg = parseRegister(childEl, deviceSize, skipped);
                if (reg != null) {
                    registers.add(new SvdRegister(childPrefix + reg.name(),
                            reg.offset() + effective, reg.size(), reg.fields(),
                            reg.skippedFields(), reg.derivedFrom()));
                }
            } else if ("cluster".equals(childEl.getTagName())) {
                flattenCluster(childEl, deviceSize, registers, skipped, effective, childPrefix);
            }
        }
    }

    private static SvdRegister parseRegister(Element regEl, int deviceSize, List<String> skipped,
            boolean dimExpansion) {
        String name = textOf(firstChildElement(regEl, "name"));
        if (name == null || name.isBlank()) {
            return null;
        }
        long offset = parseLongOr(textOf(firstChildElement(regEl, "addressOffset")), -1);
        if (offset < 0) {
            skipped.add("register:" + safeName(name) + " (no parseable <addressOffset>)");
            return null;
        }
        String derivedFrom = regEl.getAttribute("derivedFrom");
        if (derivedFrom.isBlank()) {
            derivedFrom = null;
        }
        Element sizeEl = firstChildElement(regEl, "size");
        int size = (int) parseLongOr(textOf(sizeEl), deviceSize > 0 ? deviceSize : 32);
        if (derivedFrom != null && sizeEl == null) {
            // No explicit <size>: resolved from the derivedFrom target later.
            size = 0;
        } else if (size <= 0 || size % 8 != 0 || size > 64) {
            skipped.add("register:" + safeName(name) + " (unsupported size " + size + ")");
            return null;
        }
        if (!dimExpansion && (name.contains("[%s]") || name.contains("%s"))) {
            skipped.add("register:" + safeName(name) + " (dim arrays unsupported)");
            return null;
        }
        // Nested <field> definitions become bit-field struct members where
        // they pack cleanly; anything we cannot represent is reported back.
        // A derived register with no <fields> element inherits the target's
        // field list, represented as a null list until resolution.
        List<String> skippedFields = new ArrayList<>();
        Element fieldsEl = firstChildElement(regEl, "fields");
        List<SvdField> fields =
                derivedFrom != null && fieldsEl == null ? null : new ArrayList<>();
        if (fieldsEl != null) {
            int nextBit = 0;
            boolean hasDerivedFields = false;
            NodeList fieldNodes = fieldsEl.getChildNodes();
            for (int k = 0; k < fieldNodes.getLength(); k++) {
                Node fn = fieldNodes.item(k);
                if (!(fn instanceof Element fel) || !"field".equals(fel.getTagName())) {
                    continue;
                }
                String fname = textOf(firstChildElement(fel, "name"));
                String fieldDerivedFrom = fel.getAttribute("derivedFrom");
                if (fieldDerivedFrom.isBlank()) {
                    fieldDerivedFrom = null;
                }
                long bitOffset = parseLongOr(textOf(firstChildElement(fel, "bitOffset")), -1);
                long bitWidth = parseLongOr(textOf(firstChildElement(fel, "bitWidth")), -1);
                String range = textOf(firstChildElement(fel, "bitRange"));
                if (bitOffset < 0 && range != null) {
                    long[] loHi = parseBitRange(range);
                    if (loHi != null) {
                        bitOffset = loHi[0];
                        bitWidth = loHi[1] - loHi[0] + 1;
                    }
                }
                if (bitOffset < 0) {
                    long lsb = parseLongOr(textOf(firstChildElement(fel, "lsb")), -1);
                    long msb = parseLongOr(textOf(firstChildElement(fel, "msb")), -1);
                    if (msb >= lsb && lsb >= 0) {
                        bitOffset = lsb;
                        bitWidth = msb - lsb + 1;
                    }
                }
                if (fname == null || fname.isBlank()) {
                    skippedFields.add("field:" + safeName(fname == null ? "?" : fname)
                            + " (unparseable or out-of-range bit position)");
                    continue;
                }
                if (fieldDerivedFrom != null) {
                    // Derived field: unresolved position/width are kept as
                    // sentinels and filled from the derivedFrom target after
                    // the loop; explicit values are already parsed above.
                    fields.add(new SvdField(fname,
                            bitOffset < 0 ? -1 : (int) bitOffset,
                            bitWidth <= 0 ? 0 : (int) bitWidth, fieldDerivedFrom));
                    hasDerivedFields = true;
                    continue;
                }
                if (bitOffset < 0 || bitWidth <= 0 || bitOffset + bitWidth > size) {
                    skippedFields.add("field:" + safeName(fname)
                            + " (unparseable or out-of-range bit position)");
                    continue;
                }
                // Contiguity cannot be judged while derived fields are still
                // unresolved sentinels; re-checked after resolution instead.
                if (!hasDerivedFields && bitOffset != nextBit) {
                    // Not contiguous with the previous field: Ghidra bit-field
                    // members cannot represent the gap cleanly at the plain
                    // level we target. Keep the register but skip its fields.
                    skippedFields.add("field:" + safeName(fname)
                            + " (non-contiguous field packing unsupported)");
                    continue;
                }
                fields.add(new SvdField(fname, (int) bitOffset, (int) bitWidth, null));
                nextBit += (int) bitWidth;
            }
            if (hasDerivedFields) {
                resolveDerivedFields(fields, skippedFields, size);
                int resolvedNextBit = 0;
                List<SvdField> packed = new ArrayList<>(fields.size());
                for (SvdField field : fields) {
                    if (field.lsb() != resolvedNextBit) {
                        skippedFields.add("field:" + safeName(field.name())
                                + " (non-contiguous field packing unsupported)");
                        continue;
                    }
                    packed.add(field);
                    resolvedNextBit += field.width();
                }
                fields.clear();
                fields.addAll(packed);
            }
        }
        return new SvdRegister(name, offset, size, fields, skippedFields, derivedFrom);
    }

    /**
     * Resolve field-level &lt;field derivedFrom="..."&gt; references within
     * one register's parsed field list. A derived field keeps its own name
     * and any explicitly-parsed bit position/width and inherits the missing
     * pieces from the referenced field; chains are resolved ancestor-first so
     * a derived field may inherit from another derived field, with cycle
     * protection. On a cycle or a target that does not name a field of the
     * same register, the field is dropped and a note is added to
     * {@code skippedFields}. After resolution any field still lacking a
     * bit position or width (inheritance failed to provide it) is dropped
     * with the usual unparseable-position note, as is one falling outside
     * the register's bits.
     */
    private static void resolveDerivedFields(List<SvdField> fields,
            List<String> skippedFields, int regSizeBits) {
        Map<String, SvdField> byName = new LinkedHashMap<>();
        for (SvdField field : fields) {
            byName.putIfAbsent(field.name(), field);
        }
        List<SvdField> out = new ArrayList<>(fields.size());
        for (SvdField field : fields) {
            if (field.derivedFrom() == null) {
                out.add(field);
                continue;
            }
            Set<String> visited = new HashSet<>();
            visited.add(field.name());
            List<SvdField> chain = new ArrayList<>();
            String ref = field.derivedFrom();
            boolean broken = false;
            while (ref != null) {
                if (!visited.add(ref)) {
                    skippedFields.add("field:" + safeName(field.name())
                            + " (derivedFrom: derivation cycle at '" + ref + "')");
                    broken = true;
                    break;
                }
                SvdField target = byName.get(ref);
                if (target == null) {
                    skippedFields.add("field:" + safeName(field.name())
                            + " (derivedFrom: target '" + ref
                            + "' not found in register)");
                    broken = true;
                    break;
                }
                chain.add(target);
                ref = target.derivedFrom();
            }
            if (broken) {
                continue;
            }
            // Fold from the ultimate ancestor down: the nearest link
            // carrying an explicit value wins over the inherited one.
            int lsb = field.lsb();
            int width = field.width();
            for (int i = chain.size() - 1; i >= 0; i--) {
                SvdField link = chain.get(i);
                if (lsb < 0 && link.lsb() >= 0) {
                    lsb = link.lsb();
                }
                if (width <= 0 && link.width() > 0) {
                    width = link.width();
                }
            }
            if (lsb < 0 || width <= 0 || lsb + width > regSizeBits) {
                skippedFields.add("field:" + safeName(field.name())
                        + " (unparseable or out-of-range bit position)");
                continue;
            }
            out.add(new SvdField(field.name(), lsb, width, null));
        }
        fields.clear();
        fields.addAll(out);
    }

    /** "[VMSN:MSB]" SVD bitRange form -> {lsb, msb}; null when unparseable. */
    private static long[] parseBitRange(String range) {
        if (range == null) {
            return null;
        }
        String s = range.trim().replaceAll("[\\[\\]]", "").replaceAll("[\\s,:]+", ":");
        String[] parts = s.split(":");
        if (parts.length != 2) {
            return null;
        }
        try {
            long msb = parseLongOr(parts[0], -1);
            long lsb = parseLongOr(parts[1], -1);
            if (msb < 0 || lsb < 0 || msb < lsb) {
                return null;
            }
            return new long[] {lsb, msb};
        } catch (NumberFormatException e) {
            return null;
        }
    }

    // -----------------------------------------------------------------------
    // SVD application
    // -----------------------------------------------------------------------

    /**
     * Materialize a parsed SVD into the program inside the caller's
     * transaction. Per-peripheral failures (bad base for that block, name
     * collisions) are reported per peripheral instead of failing the import.
     */
    private static Response applySvd(Program program, SvdModel model) {
        DataTypeManager dtm = program.getDataTypeManager();
        Memory memory = program.getMemory();
        SymbolTable symbols = program.getSymbolTable();

        List<Map<String, Object>> periphResults = new ArrayList<>();
        int structsCreated = 0;
        int registersImported = 0;
        int bitfieldsCreated = 0;
        int bitfieldsSkipped = 0;
        int blocksCreated = 0;
        int labelsCreated = 0;
        List<String> globalSkipped = new ArrayList<>();

        for (SvdPeripheral periph : model.peripherals()) {
            Map<String, Object> pr = new LinkedHashMap<>();
            pr.put("name", periph.name());
            pr.put("base", "0x" + Long.toHexString(periph.baseAddress()));

            // ---- structure with one member per register ----
            String structName = periph.name() + "_T";
            int structSize = 0;
            try {
                DataType existing = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);
                if (existing != null) {
                    dtm.remove(existing);
                }
                StructureDataType struct = new StructureDataType(structName, 0);
                int nextOffset = 0;
                for (SvdRegister reg : periph.registers()) {
                    int regSizeBytes = reg.size() / 8;

                    // Reserve padding up to the register's offset so member
                    // offsets match the SVD addressOffsets exactly.
                    if (reg.offset() > nextOffset) {
                        int pad = (int) (reg.offset() - nextOffset);
                        struct.add(new ArrayDataType(ByteDataType.dataType, pad, 1),
                                "_reserved_" + nextOffset, null);
                    }

                    DataType regType;
                    if (reg.fields().isEmpty()) {
                        regType = unsignedTypeFor(reg.size());
                        struct.add(regType, reg.name(), null);
                    } else {
                        // One bit-field struct per register: members in
                        // declaration order (SVD fields are listed from bit 0
                        // up), each a bit-field of the register's uint base.
                        String fieldsStructName = structName + "_" + reg.name() + "_T";
                        StructureDataType fieldsStruct =
                                new StructureDataType(fieldsStructName, 0);
                        int packedBits = 0;
                        boolean allPacked = true;
                        for (SvdField field : reg.fields()) {
                            DataType base = unsignedTypeFor(reg.size());
                            try {
                                fieldsStruct.addBitField(base, field.width(), field.name(), null);
                                packedBits += field.width();
                            } catch (Exception e) {
                                allPacked = false;
                                break;
                            }
                        }
                        if (allPacked) {
                            // Bit-field structs must fill the register word;
                            // pad the tail with an anonymous reserved field.
                            if (packedBits < reg.size()) {
                                try {
                                    fieldsStruct.addBitField(unsignedTypeFor(reg.size()),
                                            reg.size() - packedBits,
                                            "_reserved_bits", null);
                                    packedBits = reg.size();
                                } catch (Exception e) {
                                    allPacked = false;
                                }
                            }
                        }
                        if (allPacked && packedBits == reg.size()) {
                            regType = fieldsStruct;
                            try {
                                dtm.addDataType(fieldsStruct,
                                        DataTypeConflictHandler.REPLACE_HANDLER);
                                bitfieldsCreated += reg.fields().size();
                            } catch (Exception e) {
                                regType = unsignedTypeFor(reg.size());
                                bitfieldsSkipped += reg.fields().size();
                            }
                        } else {
                            regType = unsignedTypeFor(reg.size());
                            bitfieldsSkipped += reg.fields().size();
                        }
                    }
                    struct.insertAtOffset((int) reg.offset(), regType, regSizeBytes,
                            reg.name(), null);
                    nextOffset = (int) (reg.offset() + regSizeBytes);
                    registersImported++;
                }
                if (struct.getLength() == 0) {
                    pr.put("struct_skipped", "no registers imported");
                }
                dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
                structSize = struct.getLength();
                structsCreated++;
                pr.put("struct", structName);
                pr.put("struct_size", struct.getLength());
                int regSkipped = 0;
                for (SvdRegister reg : periph.registers()) {
                    regSkipped += reg.skippedFields().size();
                }
                if (regSkipped > 0) {
                    pr.put("fields_skipped", regSkipped);
                }
            } catch (Exception e) {
                pr.put("struct_error", e.getMessage());
            }

            // ---- volatile MMIO block over the peripheral's range ----
            Address base = ServiceUtils.parseAddress(program, "0x" + Long.toHexString(periph.baseAddress()));
            if (base == null) {
                pr.put("base_error", ServiceUtils.getLastParseError());
                periphResults.add(pr);
                continue;
            }
            if (structSize > 0) {
                try {
                    Address end = base.add(structSize - 1);
                    if (memory.getBlock(base) == null && memory.getBlock(end) == null) {
                        MemoryBlock block = memory.createUninitializedBlock(
                                periph.name(), base, structSize, false);
                        block.setRead(true);
                        block.setWrite(true);
                        block.setExecute(false);
                        block.setVolatile(true);
                        block.setComment("Peripheral " + periph.name()
                                + " imported from CMSIS-SVD (device: " + model.deviceName() + ")");
                        blocksCreated++;
                        pr.put("block", periph.name());
                    } else {
                        pr.put("block_skipped", "address range overlaps existing block '"
                                + memory.getBlock(base).getName() + "'");
                    }
                } catch (Exception e) {
                    pr.put("block_error", e.getMessage());
                }
            }

            // ---- label at the base ----
            try {
                if (symbols.createLabel(base, periph.name(), SourceType.USER_DEFINED) != null) {
                    labelsCreated++;
                    pr.put("label", periph.name());
                }
            } catch (Exception e) {
                pr.put("label_error", e.getMessage());
            }

            if (!periph.skipped().isEmpty()) {
                pr.put("skipped", periph.skipped());
            }
            periphResults.add(pr);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "success");
        out.put("device", model.deviceName());
        out.put("peripherals", periphResults);
        out.put("peripherals_imported", periphResults.size());
        out.put("structs_created", structsCreated);
        out.put("registers_imported", registersImported);
        out.put("bitfields_created", bitfieldsCreated);
        out.put("bitfields_skipped", bitfieldsSkipped);
        out.put("blocks_created", blocksCreated);
        out.put("labels_created", labelsCreated);
        out.put("skipped", globalSkipped);
        return Response.ok(out);
    }

    private static DataType unsignedTypeFor(int sizeBits) {
        return switch (sizeBits) {
            case 8 -> ByteDataType.dataType;
            case 16 -> ShortDataType.dataType;
            case 32 -> IntegerDataType.dataType;
            case 64 -> LongLongDataType.dataType;
            default -> UnsignedIntegerDataType.dataType;
        };
    }

    // -----------------------------------------------------------------------
    // Shared JSON helpers
    // -----------------------------------------------------------------------

    private static Map<String, Object> blockToJson(MemoryBlock block) {
        String perms = (block.isRead() ? "r" : "-") + (block.isWrite() ? "w" : "-")
                + (block.isExecute() ? "x" : "-");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", block.getName());
        m.put("start", block.getStart().toString(false));
        m.put("start_full", block.getStart().toString());
        m.put("end", block.getEnd().toString(false));
        m.put("size", block.getSize());
        m.put("permissions", perms);
        m.put("volatile", block.isVolatile());
        m.put("initialized", block.isInitialized());
        m.put("overlay", block.isOverlay());
        m.put("block_type", block.getType().toString());
        m.put("source", block.getSourceName() != null ? block.getSourceName() : "");
        m.put("address_space", block.getStart().getAddressSpace().getName());
        String comment = block.getComment();
        m.put("comment", comment != null ? comment : "");
        return m;
    }

    private static String spaceTypeName(int type) {
        return switch (type) {
            case AddressSpace.TYPE_RAM -> "ram";
            case AddressSpace.TYPE_CODE -> "code";
            case AddressSpace.TYPE_JOIN -> "join";
            case AddressSpace.TYPE_EXTERNAL -> "external";
            case AddressSpace.TYPE_STACK -> "stack";
            case AddressSpace.TYPE_REGISTER -> "register";
            case AddressSpace.TYPE_OTHER -> "other";
            default -> "unknown(" + type + ")";
        };
    }

    private static Element firstChildElement(Element parent, String tag) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n instanceof Element el && tag.equals(el.getTagName())) {
                return el;
            }
        }
        return null;
    }

    private static String firstChildText(Element parent, String tag, String defaultValue) {
        Element el = firstChildElement(parent, tag);
        String text = el == null ? null : textOf(el);
        return text != null && !text.isBlank() ? text.trim() : defaultValue;
    }

    private static String textOf(Element el) {
        return el == null ? null : el.getTextContent();
    }

    /** Parse a long from SVD numeric text: 0x<hex>, decimal, or bare hex with optional suffixes. */
    private static long parseLongOr(String text, long defaultValue) {
        if (text == null) {
            return defaultValue;
        }
        String s = text.trim().replaceAll("[uUlL]+$", "");
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                return Long.parseUnsignedLong(s.substring(2), 16);
            }
            if (s.matches("[0-9]+")) {
                return Long.parseLong(s);
            }
            // SVD also allows bare hex without a 0x prefix in some packs.
            if (s.matches("[0-9a-fA-F]+")) {
                return Long.parseUnsignedLong(s, 16);
            }
        } catch (NumberFormatException ignored) {
            // fall through
        }
        return defaultValue;
    }

    private static String safeName(String s) {
        return s == null ? "?" : s.replaceAll("[^A-Za-z0-9_.\\[\\]-]", "_");
    }
}
