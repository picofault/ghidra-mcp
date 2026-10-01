# Adding a New MCP Tool (Endpoint)

A permanent recipe for adding tools to ghidra-mcp: new HTTP endpoints on the
Java side that the Python bridge turns into MCP tools automatically. Written
after building the `patching` group (`/patch_bytes`, `/assemble`,
`src/main/java/com/xebyte/core/PatchService.java`) — every file path, command,
and pitfall below was hit for real on that change. Use it for the next feature
(ROP gadget search, CFG export, equates, BSim endpoints, ...).

Line numbers are cited as of the 7.0.0 + patching tree and will drift; the
symbols they point at will not.

## How a tool is born: the pipeline

There is exactly one way a tool comes into existence, and the Python bridge is
not part of it:

1. **Annotations.** A method on a service class carries
   `@McpTool(path = "/my_tool", method = "POST", description = "...", category = "mygroup")`
   (`src/main/java/com/xebyte/core/McpTool.java`) and each parameter carries
   `@Param` (`src/main/java/com/xebyte/core/Param.java`). The class usually
   carries `@McpToolGroup(value = "mygroup", description = "...")`
   (`src/main/java/com/xebyte/core/McpToolGroup.java`) — the group value is
   the fallback category and the unit the bridge lazy-loads by.
2. **AnnotationScanner** (`src/main/java/com/xebyte/core/AnnotationScanner.java`)
   reflectively discovers `@McpTool` methods on the service instances it is
   handed, converts HTTP query/body values to Java argument types from the
   `@Param` declarations, and produces `ToolDescriptor`s (path, method,
   category, params, description) for `/mcp/schema`.
3. **HTTP route.** Each server loops over `scanner.getEndpoints()` and calls
   `createContext(ep.path(), ...)`: GUI plugin at
   `src/main/java/com/xebyte/GhidraMCPPlugin.java:651`, headless server at
   `src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java:397`.
4. **Bridge auto-registration.** On `connect_instance`, the Python bridge
   fetches `/mcp/schema` and registers one MCP tool per entry
   (`python/bridge_mcp_ghidra/registry.py`, `_parse_schema` in
   `python/bridge_mcp_ghidra/schema.py`). **No Python change is ever needed
   to add a tool.** Do not touch `python/`.

Consequence: a tool exists iff its service instance is passed to a server's
`new AnnotationScanner(...)`. An annotated method on a class nobody registers
is dead code that still compiles.

## Checklist for a new service

### 1. Write the service class

Create `src/main/java/com/xebyte/core/MyService.java`.

- **Read-only template**: `ListingService.java` — constructor takes
  `ProgramProvider` only.
- **Mutating template**: `SymbolLabelService.java` (rich examples) or
  `PatchService.java` (minimal) — constructor takes
  `(ProgramProvider, ThreadingStrategy)`.
- Class-level `@McpToolGroup(value = "mygroup", description = "...")`.
- One public method per endpoint; keep overloads without annotations for
  internal reuse (the scanner only registers annotated methods).
- Return `Response.ok(JsonHelper.mapOf(...))` / `Response.err("...")`
  (`src/main/java/com/xebyte/core/Response.java`). Never return hand-built
  JSON strings; `Response.text(...)` is deprecated for exactly that reason.
- **Descriptions are the tool's UI.** The `@McpTool description` and every
  `@Param description` are what the AI agent reads to decide how to call the
  tool. Say the accepted input shapes ("0x<hex> or <space>:<hex>"), the
  failure modes, and which sibling tool to use instead. `ParamDescriptionCoverageTest`
  (Java, offline) fails the build on an undescribed `@Param`.

### 2. Register it in BOTH servers

| Where | What to add |
| --- | --- |
| `GhidraMCPPlugin.java` | field (line ~289), construction (line ~313), extra vararg in the `new AnnotationScanner(...)` call (line ~651) |
| `headless/HeadlessEndpointHandler.java` | field, construction in the constructor (line ~81), a getter next to `getPatchService()` (line ~100) |
| `headless/GhidraMCPHeadlessServer.java` | extra `endpointHandler.getMyService()` vararg in the scanner call (line ~397) |
| `src/test/java/com/xebyte/offline/ServiceFactory.java` | add to `buildAllServices()` so the offline scanner tests see it |

GUI-only (needs `PluginTool`, like `DebuggerService`) or headless-only (like
`HeadlessManagementService`) is legitimate — but decide it deliberately,
because the `servers` field in the catalog is derived from this wiring.

### 3. Update the endpoint catalog

`tests/endpoints.json` is the enforced, authoritative catalog. Entries are
sorted by `path`. Add:

```json
{
  "path": "/my_tool",
  "method": "POST",
  "category": "mygroup",
  "params": ["address", "program"],
  "servers": ["gui", "headless"],
  "description": "First sentence shows up in the README API reference."
}
```

Also bump `total_endpoints` and add your category to the `categories` map at
the top. Then stamp/verify the `servers` fields:

```bash
.venv/bin/python -m tools.audit_server_scope --write
.venv/bin/python -m tools.audit_server_scope --check
```

`EndpointsJsonParityTest` (Java, offline) compares the catalog against a live
annotation scan: every scanned path must be present, method must match, and
declared `@Param` names must appear in `params`. Extra catalog params are
tolerated (documented aliases), missing ones are not.

### 4. Propagate the counts (the ratchet)

Adding endpoints changes four derived numbers — TOTAL, GUI, HEADLESS, SHARED —
and `tests/unit/test_published_counts.py` pins them in ~11 files. The fix
order that converges fastest:

1. Edit `tests/endpoints.json` (step 3).
2. `python -m tools.audit_server_scope --write` then `--check`.
3. `python -m tools.gen_readme_api_reference --write` — regenerates the
   README's API-reference block (between the `BEGIN/END GENERATED API
   REFERENCE` markers). If your category is new, also add it to
   `CATEGORY_SECTIONS` in `tools/gen_readme_api_reference.py` first, or the
   section heading renders as "(uncategorized)".
4. Run `pytest tests/unit/ --no-cov -q` and let each failure name the file
   and the stale literal. Expect to touch:
   - `README.md` (several prose sites beyond the generated block)
   - `CLAUDE.md`, `AGENTS.md`, `CONTRIBUTING.md`, `ROADMAP.md`
   - `.github/ISSUE_TEMPLATE/feature_request.yml`
   - `src/main/resources/extension.properties` and
     `src/main/resources/META-INF/MANIFEST.MF` (GUI count only)
   - `src/main/java/com/xebyte/GhidraMCPPlugin.java` ("Provides N endpoints"
     javadoc, GUI count)
   - `docs/releases/README.md` (current unreleased entry)
   - `docs/Context-Window-Analysis.md` (the "catalog stands at **N** today"
     disclaimer on a dated measurement — it must track the catalog even
     though the body numbers deliberately do not)
5. `CHANGELOG.md` is excluded from the sweep (it is history), but the top
   unreleased entry's header counts and an `### Added` bullet should still be
   updated by hand.

**Hardcoded service lists** that fail loudly (good) but must be updated by
hand:

- `tools/audit_endpoint_categories.py` — `SCANNED_SERVICES` tuple.
- `src/test/java/com/xebyte/offline/ServiceFactory.java` — `buildAllServices()`.
- `tests/unit/test_audit_server_scope.py` — the shared-service count literal
  (`assert len(gui & headless) == N`) when your service is on both servers.

### 5. CHANGELOG

Add an entry under the current unreleased version's `### Added`, matching the
existing style (bold feature name, what it does, notable behavior).

## Mutation rules (read this before writing a write-tool)

- **Transactions.** Every program mutation runs inside
  `int tx = program.startTransaction("Human readable name"); try { ... } finally { program.endTransaction(tx, success); }`.
  The name shows in Ghidra's undo history.
- **ThreadingStrategy.** GUI mode must mutate on the Swing EDT; headless runs
  direct. That is what the injected `ThreadingStrategy`
  (`src/main/java/com/xebyte/core/ThreadingStrategy.java`) abstracts:
  `executeWrite(program, txName, action)` opens the transaction for you on the
  right thread. Older code uses bare `program.startTransaction` or
  `SwingUtilities.invokeAndWait`; both patterns exist in the tree — mirror the
  service you templated from, and never call Swing directly in new code.
- **`ParamSource.BODY` for POST inputs.** Query-source params on a POST
  endpoint silently bind nothing. `program` is conventionally
  `@Param(value = "program", defaultValue = "", ...)` and resolved via
  `ServiceUtils.getProgramOrError(programProvider, programName)`.
- **Addresses**: always `ServiceUtils.parseAddress(program, str)` — it accepts
  `0x<hex>`, `<space>:<hex>` (`mem:1000`), and overlay spaces. On `null`,
  return `Response.err(ServiceUtils.getLastParseError())` immediately:
  the error message is a **ThreadLocal**, so call `parseAddress` on the HTTP
  worker thread *before* entering any `threadingStrategy.execute*` lambda
  (the lambda may run on the EDT, where the caller's ThreadLocal is
  invisible).
- **Address-space caveat**: embedded/MCU targets are not
  address-space-agnostic. Copy the standard `@Param` address description that
  points users at `get_address_spaces` (see any existing service).
- **Report before-state for reversible mutations.** `/patch_bytes` returns
  `previous_bytes` so an agent can revert; if the write invalidates derived
  state (e.g. patching over code units makes the listing stale), say so in a
  `warnings` field and name the repair tool (`clear_flow_and_repair`,
  `reanalyze`).

## Verification recipe

Run all of these before declaring done:

```bash
# 1. Java build (Gradle is the default backend; reads jars from the install)
./gradlew buildExtension "-PGHIDRA_INSTALL_DIR=/opt/ghidra"

# 2. Java offline test tier (parity, param coverage, aliases)
./gradlew test --tests 'com.xebyte.offline.*' "-PGHIDRA_INSTALL_DIR=/opt/ghidra"

# 3. Python unit suite (includes the published-count ratchet)
.venv/bin/python -m pytest tests/unit/ --no-cov -q

# 4. Catalog audits
.venv/bin/python -m tools.audit_server_scope --check
.venv/bin/python -m tools.audit_endpoint_categories --quiet
.venv/bin/python -m tools.gen_readme_api_reference   # check mode: exit 1 on drift
```

### Headless smoke test (no Docker needed)

The most valuable check: boot the real headless server against a small system
binary and exercise the new endpoint over HTTP. The classpath recipe is
adapted from `docker/entrypoint.sh`:

```bash
GHIDRA_HOME=/opt/ghidra
CLASSPATH="build/libs/GhidraMCP-7.0.0.jar"
for jar in ${GHIDRA_HOME}/Ghidra/Framework/*/lib/*.jar \
           ${GHIDRA_HOME}/Ghidra/Features/*/lib/*.jar \
           ${GHIDRA_HOME}/Ghidra/Processors/*/lib/*.jar; do
  CLASSPATH="${CLASSPATH}:${jar}"
done
java -Xmx2g -Dghidra.home=${GHIDRA_HOME} -Dapplication.name=GhidraMCP \
  -classpath "${CLASSPATH}" \
  com.xebyte.headless.GhidraMCPHeadlessServer \
  --port 18089 --bind 127.0.0.1 --file /bin/true &
```

`/bin/true` imports and auto-analyzes in about a second; the log prints
`Registered N REST API endpoints` — N should equal the catalog's headless
count exactly. Then:

```bash
# The new tool is published:
curl -s http://127.0.0.1:18089/mcp/schema | grep -o '/my_tool'
# Happy path (functions are already analyzed; pick one from):
curl -s "http://127.0.0.1:18089/list_functions?limit=3"
curl -s -X POST http://127.0.0.1:18089/my_tool \
  -H 'Content-Type: application/json' -d '{"address":"0x001027e0", ...}'
# Error paths: bad address, bad input shape, out-of-range target.
kill %1
```

Verify mutations by reading state back through an existing read endpoint
(e.g. `/read_memory`) rather than trusting the write response alone.

## Pitfalls (all hit for real)

- **The Ghidra assembler API is not where you expect.** In 12.1.3,
  `ghidra.app.plugin.assembler.Assemblers` / `Assembler` live in
  `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`, not Base.jar.
  Verify any Ghidra API against the installed jars before writing code:
  `unzip -o <jar> 'path/to/Class.class' -d /tmp/x && javap -classpath /tmp/x <fqcn>`.
  The API changes across Ghidra versions — do not trust memory or blog posts.
- **`assembleLine` vs `assemble`.** `Assembler.assembleLine(addr, line)`
  returns `byte[]` without touching the program — ideal for validating the
  whole input before mutating. `Assembler.assemble(addr, lines...)` writes
  the bytes AND creates code units (it is the GUI Patch Instruction action);
  it must run inside a transaction. But branch encodings are
  **position-dependent**: when pre-assembling a `;`-separated list, measure
  line N at `base + length(lines 0..N-1)` with a running cursor, or your
  total length (and your previous-bytes capture) is wrong.
- **`Memory.setBytes` refuses defined code units.** Raw byte writes over
  bytes owned by an existing instruction or data item fail with
  "Memory change conflicts with instruction at ...". The assembler path
  clears/replaces code units itself; a raw-patcher must either error with
  guidance (what `/patch_bytes` does: use `assemble`, or
  `clear_flow_and_repair` first) or clear the listing itself. Decide
  explicitly — silently clearing code units is a destructive listing change.
- **`RegenerateEndpointsJson` is Maven-oriented.** It regenerates
  `tests/endpoints.json` from a live scan, gated on
  `-Dregenerate=true` — but `build.gradle`'s `test {}` block does not forward
  that property, so under Gradle it no-ops silently. Hand-edit the catalog
  (sorted by path) and let `EndpointsJsonParityTest` plus
  `audit_server_scope --write` do the checking.
- **New categories need two extra touches** beyond the annotation: the
  `categories` map in `tests/endpoints.json` and `CATEGORY_SECTIONS` in
  `tools/gen_readme_api_reference.py` (or the README heading says
  "(uncategorized)").
- **The count ratchet has a long tail.** Even after the pinned sites are
  fixed, a dated doc with a disclaimer (`docs/Context-Window-Analysis.md`)
  tracks the catalog size. Let `test_published_counts.py` failures drive —
  each one names the file and the expected number.
- **Description first sentence == README summary.** The README generator uses
  the first sentence of the catalog description. Front-load it.
- **Headless `--file` import does not fully auto-analyze.** The listing after
  import is sparse (PLT and import-time code only; function bodies stay
  undefined — `disassemble_function` reports `body_degenerate: true`). Any
  endpoint that walks defined instructions (gadget scans, instruction search,
  xref-based tools) sees almost nothing until you `POST /reanalyze` and wait
  for `analyzing: false`. Smoke tests for such endpoints must reanalyze first
  or they will "pass" against a near-empty listing.
- **There is no `FlowType.RETURN` constant (12.1.3).** Returns are the
  TERMINATOR family: classify with `flowType.isTerminal() && !isCall() &&
  !isJump()`; JOP dispatchers are `isJump() && isComputed()`; COOP
  dispatchers are `isCall() && isComputed()`. And `FlowType` lives in
  `ghidra.program.model.symbol`, not `listing` — check the jar, not your
  memory.
- **`PseudoDisassembler` (`ghidra.app.util`, headless-safe) disassembles at
  any address without mutating the program** — the way to find unintended
  (mid-instruction) gadgets that the listing cannot represent.
  `getNormalizedDisassemblyAddress(program, addr)` maps odd offsets to
  aligned Thumb addresses; it is identity on x86. Listing `Instruction`s and
  `PseudoInstruction`s expose the same surface (`getFlowType`,
  `getFallThrough`, `getBytes`, `toString`), so one record builder can serve
  both scan engines.
- **PIE binaries are rebased in Ghidra.** `/bin/true` loads at image base
  `0x100000`, so every address is `objdump` vaddr + `0x100000`. Cross-check
  smoke-test gadgets against objdump with that delta or you will chase
  ghosts.
- **`BasicBlockModel` destinations can leave the function.** Tail calls/jumps
  produce `CodeBlockReference`s whose destination block is outside
  `func.getBody()`. An intra-function CFG must filter edges to destination
  starts inside the body, and compute `is_exit` *after* that filtering, or
  tail-calling blocks never show as exits. In return, `CodeBlock` is an
  `AddressSetView`, so `listing.getInstructions(block, true)` feeds an
  include-instructions mode directly. Fall-through edges report
  `hasFallthrough()` with neither `isJump()` nor `isCall()`; classify in the
  order call → conditional-jump → jump (`isComputed()` → indirect) →
  fallthrough.
- **PLT thunks and stripped binaries shape the smoke test.** A PLT thunk
  (`free`, `abort`, ...) has a degenerate body — the CFG endpoint's
  "undefined or empty body" error path *is* the correct response there. And a
  stripped `/bin/true` has no `main` symbol: target the ELF entry instead
  (`readelf -h` entry + the 0x100000 PIE delta; Ghidra names it `entry`) or
  a `FUN_*` address, and cross-check by address, not by name.
- **The shared-count ratchet site is easy to miss.** Beyond the 256/242/229
  literals, `CLAUDE.md` carries "215 endpoints are on both" — the
  both-servers count. `test_published_counts.py` names it, but only after
  the total/GUI/headless sites are fixed, so sweep for the shared count
  (`audit_server_scope`'s `gui+headless` figure) in the same pass.
- **`Instruction.toString()` does not substitute equates (12.1.3).** It
  returns Ghidra's *default* operand form, so every endpoint that renders
  instructions through `toString()` (`disassemble_function`, CFG
  include-instructions, gadget text) shows the raw number even with an equate
  attached. The GUI listing's renderer is
  `ghidra.program.model.listing.CodeUnitFormat` (SoftwareModeling.jar) —
  `CodeUnitFormat.DEFAULT.getRepresentationString(instr)` and
  `getOperandRepresentationString(instr, opIndex)` are what substitute the
  equate name. Smoke tests for equate/reference markup must verify through
  `CodeUnitFormat` (e.g. via `run_script_inline` with
  `GHIDRA_MCP_ALLOW_SCRIPTS=1`), not by re-reading `disassemble_function` —
  and tool descriptions must not promise the substitution where the endpoint
  cannot show it. Also note `Equate` has no `deleteEquate()` in 12.1.3:
  whole-equate deletion is `EquateTable.removeEquate(name)`, and an equate
  with zero references persists in the table until then.
- **`run_script_inline` wraps your source unless it contains the literal
  `extends GhidraScript`.** A fully-qualified
  `extends ghidra.app.script.GhidraScript` does NOT match the wrapper's
  substring check, so your complete class gets nested inside a generated
  `run()` and fails with "illegal start of expression". Import
  `ghidra.app.script.GhidraScript` and write `extends GhidraScript` — then
  the source is used verbatim (and `public class X` names the file). The
  script lands in `~/ghidra_scripts/`; delete it after the smoke test.
- **Bulk sed on release-history docs overshoots.** Running
  `sed -i 's/\b243\b/246/g'` across the ratchet file list also rewrites
  *historical* entries in `docs/releases/README.md` ("241 → 243 tools" in
  the v5.9.0 section). Fix the current unreleased entry's counts, then
  `git diff` the file and restore every historical site by hand.
- **`EmulatorHelper`'s memory-write tracking covers the register space too.**
  `enableMemoryWriteTracking(true)` adds a `MemoryAccessFilter` that sees
  every space, and p-code execution writes RSP/RIP into the `register:` space,
  so `getTrackedMemoryWriteSet()` comes back polluted with
  `register:XXXX-register:XXXX` ranges. Filter to `space.isMemorySpace()`
  before reporting "what memory did this code touch" (there is no
  `AddressSpace.TYPE_MEMORY` constant in 12.1.3 — the predicate is
  `isMemorySpace()`). Enable tracking only AFTER seeding registers/memory so
  the caller's own setup writes never appear in the set.
- **"All base registers" is not a usable default register set on x86.**
  Filtering `language.getRegisters()` by `isBaseRegister()` minus
  HIDDEN/CONTEXT/FP/VECTOR yields 100+ entries on x86-64 (CR*, DR*,
  individual flag bits, FPU state, BND/K regs — ST0 does not carry TYPE_FP).
  A default "general-purpose" set needs a curated per-processor list
  (x86/AARCH64/ARM/MIPS/PowerPC), dropping names the language variant lacks
  (`program.getRegister(name) != null`), with the generic filter as fallback.
- **`EmulatorHelper` silently zero-fills uninitialized reads.** Its default
  `uninitializedRead` handler logs and continues (except during instruction
  decode, which faults); `unknownAddress` faults. So emulated code reading
  memory the caller never seeded sees 0 with no error — the tool description
  must tell callers to seed every input — and a jump to an unmapped target
  surfaces as `fault` with "Instruction decode failed (invalid memory)". Also
  seed the stack via `emu.getStackPointerRegister()` (arch-agnostic), never a
  hardcoded ESP/RSP name, and write a pointer-width return-address sentinel
  (endianness-aware) so a RET gives you a clean stop condition.
