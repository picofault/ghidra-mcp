package com.xebyte.core;

import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.QueryExeCount;
import ghidra.features.bsim.query.protocol.QueryExeInfo;
import ghidra.features.bsim.query.protocol.ResponseExe;
import ghidra.features.bsim.query.protocol.ResponseInfo;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseInsert;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for Ghidra's BSim function-similarity database: database-level
 * endpoints that create and inventory a local H2 corpus without an open
 * program. Program-dependent endpoints (ingest, query) are separate.
 */
@McpToolGroup(value = "analysis",
        description = "Completeness analysis, control flow, similarity, crypto detection, memory inspection, BSim corpus similarity")
public class BsimService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public BsimService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // bsim_create_database
    // -----------------------------------------------------------------------

    @McpTool(path = "/bsim_create_database", method = "POST",
             description = "Create a new H2 file-based BSim function-similarity database on the server's "
                         + "filesystem — first step of the library-identification workflow: create a local "
                         + "H2 corpus, then ingest reference builds (bsim_ingest_program on known OpenSSL/"
                         + "mbedTLS/zlib firmware images), then query functions in stripped firmware "
                         + "(bsim_query_function) to identify library code and map it to CVEs. Takes an H2 "
                         + "file path WITHOUT the .mv.db extension (the extension is appended "
                         + "automatically); fails if that file already exists. The database is created "
                         + "with call-graph tracking enabled so BSim's signature+callgraph correlation "
                         + "works. Works without any open program.",
             category = "analysis")
    public Response createDatabase(
            @Param(value = "db_path", source = ParamSource.BODY,
                   description = "H2 database file path WITHOUT the .mv.db extension (e.g. /data/bsim/openssl_corpus "
                               + "— the engine appends .mv.db itself). Must not already exist. Required.") String dbPath,
            @Param(value = "template", source = ParamSource.BODY, defaultValue = "medium_32",
                   description = "BSim configuration template (vector/feature configuration) to install, "
                               + "e.g. medium_32, large_32, function_neuralvector. Defaults to medium_32, "
                               + "Ghidra's general-purpose 32-bit template.") String template,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "",
                   description = "Display name for the database. Defaults to the basename of db_path.") String name) {
        if (dbPath == null || dbPath.isBlank()) {
            return Response.err("db_path parameter required (H2 file path without the .mv.db extension)");
        }
        File h2File = new File(dbPath + BSimServerInfo.H2_FILE_EXTENSION);
        if (h2File.exists()) {
            return Response.err("Database file already exists at " + h2File.getAbsolutePath()
                    + " — pick a new db_path or reuse the existing corpus (see bsim_corpus_status)");
        }
        String dbName = (name != null && !name.isBlank()) ? name.trim()
                : new File(dbPath).getName();

        BSimServerInfo serverInfo = new BSimServerInfo(dbPath);
        BSimH2FileDataSource existingBDS =
            BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);

        try (FunctionDatabase h2Database = BSimClientFactory.buildClient(serverInfo, false)) {
            CreateDatabase command = new CreateDatabase();
            command.info = new DatabaseInformation();
            command.info.databasename = dbName;
            command.config_template = template;
            command.info.trackcallgraph = true;

            ResponseInfo response = command.execute(h2Database);
            if (response == null) {
                String errMsg = h2Database.getLastError() != null
                    ? h2Database.getLastError().message : "Unknown error";
                return Response.err("bsim_create_database failed: " + errMsg);
            }

            return Response.ok(JsonHelper.mapOf(
                "status", "success",
                "path", dbPath,
                "name", dbName,
                "template", template,
                "h2_file", h2File.getAbsolutePath(),
                "message", "H2 BSim database created with call-graph tracking enabled. Next: "
                        + "ingest reference builds with bsim_ingest_program, then check coverage "
                        + "with bsim_corpus_status before bsim_query_function."));
        } catch (Exception e) {
            Msg.error(this, "bsim_create_database failed", e);
            return Response.err("bsim_create_database failed: "
                    + (e.getMessage() != null ? e.getMessage() : e.toString()));
        } finally {
            if (existingBDS == null) {
                BSimH2FileDataSource bds =
                    BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
                if (bds != null) {
                    bds.dispose();
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // bsim_corpus_status
    // -----------------------------------------------------------------------

    @McpTool(path = "/bsim_corpus_status", method = "GET",
             description = "Inventory an existing BSim H2 corpus database — what executables have been "
                         + "ingested (name, path, md5, architecture), the total executable count, and "
                         + "the database's name and call-graph-tracking setting — so an agent knows the "
                         + "corpus's coverage before querying it. Use after bsim_ingest_program and "
                         + "before bsim_query_function: if the firmware's libraries are not in the "
                         + "executable list, query results will be misses. Works without any open program.",
             category = "analysis")
    public Response corpusStatus(
            @Param(value = "db_path",
                   description = "H2 database file path WITHOUT the .mv.db extension, the same value used "
                               + "to create the corpus with bsim_create_database. Required.") String dbPath,
            @Param(value = "limit", defaultValue = "50",
                   description = "Maximum number of executable records to list. Defaults to 50; the "
                               + "response notes when the list was truncated.") int limit) {
        if (dbPath == null || dbPath.isBlank()) {
            return Response.err("db_path parameter required (H2 file path without the .mv.db extension)");
        }
        if (limit < 1) {
            return Response.err("limit must be at least 1 (got " + limit + ")");
        }

        BSimServerInfo serverInfo = new BSimServerInfo(dbPath);
        BSimH2FileDataSource existing =
            BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
        try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, false)) {
            if (!db.initialize()) {
                String errMsg = db.getLastError() != null
                    ? db.getLastError().message : "Unknown error";
                return Response.err("Cannot open BSim database at " + dbPath + ": " + errMsg);
            }
            DatabaseInformation info = db.getInfo();

            QueryExeCount qc = new QueryExeCount();
            ResponseExe cr = qc.execute(db);
            int executableCount = cr != null ? cr.recordCount : -1;

            QueryExeInfo qi = new QueryExeInfo();
            qi.limit = limit;
            qi.includeFakes = false;
            ResponseExe er = qi.execute(db);

            List<Map<String, Object>> executables = new ArrayList<>();
            int listed = 0;
            if (er != null && er.manage != null) {
                Iterator<ExecutableRecord> it = er.manage.getExecutableRecordSet().iterator();
                while (it.hasNext()) {
                    ExecutableRecord r = it.next();
                    executables.add(JsonHelper.mapOf(
                        "name", r.getNameExec(),
                        "path", r.getPath(),
                        "md5", r.getMd5(),
                        "architecture", r.getArchitecture()));
                    listed++;
                }
            }

            String note = null;
            if (executableCount > listed) {
                note = "Listing truncated by limit: showing " + listed + " of " + executableCount
                        + " executables; raise limit to see more.";
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("database_name", info != null ? info.databasename : "");
            out.put("track_callgraph", info != null ? info.trackcallgraph : false);
            out.put("executable_count", executableCount);
            out.put("executables", executables);
            if (note != null) {
                out.put("note", note);
            }
            return Response.ok(out);
        } catch (Exception e) {
            Msg.error(this, "bsim_corpus_status failed", e);
            return Response.err("bsim_corpus_status failed: "
                    + (e.getMessage() != null ? e.getMessage() : e.toString()));
        } finally {
            if (existing == null) {
                BSimH2FileDataSource bds =
                    BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
                if (bds != null) {
                    bds.dispose();
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // bsim_ingest_program
    // -----------------------------------------------------------------------

    @McpTool(path = "/bsim_ingest_program", method = "POST",
             description = "Ingest the currently open program's function signatures into an existing BSim "
                         + "H2 corpus — the middle step of the library-identification workflow: create the "
                         + "corpus (bsim_create_database), ingest a REFERENCE build (a known "
                         + "OpenSSL/mbedTLS/zlib firmware image or the unstripped target itself, so it can "
                         + "be diffed later), then query functions in stripped firmware "
                         + "(bsim_query_function) to identify matching library functions and map them to "
                         + "CVEs. Re-ingesting the same binary is BSim's own upsert keyed on the "
                         + "executable MD5; check bsim_corpus_status first to see what is already in the "
                         + "corpus. Requires a program with a valid executable MD5 (programs imported "
                         + "and analyzed headless have one; if the MD5 is missing run reanalyze first). "
                         + "Requires db_path to point at the corpus created by bsim_create_database.",
             category = "analysis")
    public Response ingestProgram(
            @Param(value = "db_path", source = ParamSource.BODY,
                   description = "H2 database file path WITHOUT the .mv.db extension — the same value "
                               + "used to create the corpus with bsim_create_database. Required.")
            String dbPath,
            @Param(value = "program", source = ParamSource.BODY, defaultValue = "",
                   description = "Target program name whose functions to ingest (omit to use the active "
                               + "program — always specify when multiple programs are open)")
            String programName) {
        if (dbPath == null || dbPath.isBlank()) {
            return Response.err("db_path parameter required (H2 file path without the .mv.db extension, "
                    + "the same corpus created by bsim_create_database)");
        }
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        String md5 = program.getExecutableMD5();
        if (md5 == null || md5.length() < 10) {
            return Response.err("Program has no valid executable MD5 hash. BSim keys ingested "
                    + "executables on the MD5: ensure the program was imported and analyzed "
                    + "(headless imports compute it automatically); if the MD5 is still empty, "
                    + "run reanalyze and retry.");
        }

        DomainFile dFile = program.getDomainFile();
        URL fileURL = dFile.getSharedProjectURL(null);
        if (fileURL == null) {
            fileURL = dFile.getLocalProjectURL(null);
        }
        // BSim re-parses repo via GhidraURL.toURL (ExecutableRecord.setRepository),
        // which only accepts ghidra: URLs or absolute local paths — a transient
        // DomainFile (headless import with no project) yields anything else, and
        // "local://<name>" is rejected the same way. ExecutableRecord documents
        // repo/path as nullable, so fall back to null instead of an unusable value.
        String repoTmp = null;
        String pathTmp = null;
        if (fileURL != null) {
            URL projectURL = null;
            try {
                projectURL = GhidraURL.getProjectURL(fileURL);
            } catch (IllegalArgumentException e) {
                projectURL = null;
            }
            if (projectURL != null && GhidraURL.isGhidraURL(projectURL.toExternalForm())) {
                repoTmp = projectURL.toExternalForm();
                String fullPath = GhidraURL.getProjectPathname(fileURL);
                // BSim adds the program name to the path, so strip it here
                int lastSlash = fullPath.lastIndexOf('/');
                pathTmp = lastSlash == 0 ? "/" : fullPath.substring(0, lastSlash);
            }
        }
        final String repo = repoTmp;
        final String path = pathTmp;

        BSimServerInfo serverInfo = new BSimServerInfo(dbPath);
        BSimH2FileDataSource existing =
            BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
        GenSignatures gensig = null;
        try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, false)) {
            if (!db.initialize()) {
                String errMsg = db.getLastError() != null
                    ? db.getLastError().message : "Unknown error";
                return Response.err("Cannot open BSim database at " + dbPath + ": " + errMsg);
            }
            DatabaseInformation dbInfo = db.getInfo();

            GenSignatures gen = new GenSignatures(dbInfo.trackcallgraph);
            gensig = gen;
            gen.setVectorFactory(db.getLSHVectorFactory());
            gen.addExecutableCategories(dbInfo.execats);
            gen.addFunctionTags(dbInfo.functionTags);
            gen.addDateColumnName(dbInfo.dateColumnName);

            // openProgram/scanFunctions read the listing; keep them off the HTTP
            // worker thread. The InsertRequest below is a pure DB write and stays
            // outside the read wrapper.
            int totalFunctions = threadingStrategy.executeRead(() -> {
                gen.openProgram(program, null, null, null, repo, path);
                FunctionManager fman = program.getFunctionManager();
                int funcCount = fman.getFunctionCount();
                Iterator<Function> iter = fman.getFunctions(true);
                gen.scanFunctions(iter, funcCount, TaskMonitor.DUMMY);
                return funcCount;
            });

            DescriptionManager manager = gen.getDescriptionManager();
            int signedFunctions = manager.numFunctions();
            if (signedFunctions == 0) {
                return Response.err("No functions with bodies found to ingest");
            }
            // De-duplicate callgraph entries to avoid SQL constraint violations
            manager.listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph());

            InsertRequest insertReq = new InsertRequest();
            insertReq.manage = manager;
            ResponseInsert insertResponse = insertReq.execute(db);
            if (insertResponse == null) {
                FunctionDatabase.BSimError lastError = db.getLastError();
                if (lastError != null &&
                    (lastError.category == ErrorCategory.Format ||
                     lastError.category == ErrorCategory.Nonfatal)) {
                    return Response.ok(JsonHelper.mapOf(
                        "status", "skipped",
                        "program", program.getName(),
                        "md5", md5,
                        "message", lastError.message));
                }
                String errMsg = lastError != null ? lastError.message : "Unknown insert error";
                return Response.err("bsim_ingest_program failed: " + errMsg);
            }

            QueryExeCount exeCount = new QueryExeCount();
            ResponseExe countResponse = exeCount.execute(db);
            int totalExes = countResponse != null ? countResponse.recordCount : -1;

            return Response.ok(JsonHelper.mapOf(
                "status", "success",
                "program", program.getName(),
                "md5", md5,
                "repo", repo,
                "path", path,
                "total_functions", totalFunctions,
                "signed_functions", signedFunctions,
                "inserted_executables", insertResponse.numexe,
                "inserted_functions", insertResponse.numfunc,
                "database_name", dbInfo.databasename,
                "total_executables_in_db", totalExes));
        } catch (Exception e) {
            Msg.error(this, "bsim_ingest_program failed", e);
            return Response.err("bsim_ingest_program failed: "
                    + (e.getMessage() != null ? e.getMessage() : e.toString()));
        } finally {
            if (gensig != null) {
                gensig.dispose();
            }
            if (existing == null) {
                BSimH2FileDataSource bds =
                    BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
                if (bds != null) {
                    bds.dispose();
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // bsim_query_function
    // -----------------------------------------------------------------------

    @McpTool(path = "/bsim_query_function", method = "GET",
             description = "Query one function of the open program against an existing BSim H2 corpus and "
                         + "return its nearest matches — the final step of the library-identification "
                         + "workflow: create the corpus (bsim_create_database), ingest reference builds "
                         + "(bsim_ingest_program on known OpenSSL/mbedTLS/zlib firmware images), then "
                         + "query a function from a STRIPPED firmware to identify library code and its "
                         + "version. An 'exact' or 'high' similarity match on a named library function "
                         + "(e.g. mbedtls_ssl_handshake or EVP_PKEY_decrypt in an ingested OpenSSL build) "
                         + "identifies the library AND its version, which maps directly to known CVEs for "
                         + "that version — the core firmware/CVE triage use case. similarity is BSim's "
                         + "vector score (0..1); significance is BSim's size-confidence metric — larger, "
                         + "more distinctive functions score higher, so tiny functions may need the "
                         + "significance threshold lowered. Each match reports executable, MD5, "
                         + "architecture, function name/address, similarity, significance, rank, and a "
                         + "confidence tier (exact >= 0.99, high >= 0.8, medium >= 0.6, low). "
                         + "same_executable marks self-hits when the match's executable MD5 equals the "
                         + "queried program's MD5 (the program was ingested into this corpus itself) — "
                         + "agents usually skip those. Resolve the function by exact start address or by "
                         + "exact name (exactly one of the two).",
             category = "analysis")
    public Response queryFunction(
            @Param(value = "db_path",
                   description = "H2 database file path WITHOUT the .mv.db extension — the same value "
                               + "used to create the corpus with bsim_create_database. Required.") String dbPath,
            @Param(value = "address", defaultValue = "",
                   description = "Function start address to query (0x hex or decimal). Provide exactly "
                               + "one of address or name. If no function starts exactly at this "
                               + "address, the function containing it is used.") String address,
            @Param(value = "name", defaultValue = "",
                   description = "Exact function name to query (e.g. FUN_00010123 or a named symbol). "
                               + "Provide exactly one of address or name.") String name,
            @Param(value = "max", defaultValue = "5",
                   description = "Maximum number of nearest-neighbor matches to return. Defaults to 5.") int max,
            @Param(value = "similarity", defaultValue = "0.7",
                   description = "Minimum similarity (BSim vector score, 0..1) for matches. Lower to "
                               + "0.5-0.6 for tiny or heavily-inlined functions. Defaults to 0.7.") double similarity,
            @Param(value = "significance", defaultValue = "10.0",
                   description = "Minimum significance (BSim size-confidence metric) for matches. Lower "
                               + "this (e.g. to 1-5) when querying small functions. Defaults to 10.0.") double significance,
            @Param(value = "program", defaultValue = "",
                   description = "Target program whose function to query (omit to use the active program "
                               + "— always specify when multiple programs are open)") String programName) {
        if (dbPath == null || dbPath.isBlank()) {
            return Response.err("db_path parameter required (H2 file path without the .mv.db extension, "
                    + "the same corpus created by bsim_create_database)");
        }
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        boolean hasAddress = address != null && !address.isBlank();
        boolean hasName = name != null && !name.isBlank();
        if (hasAddress == hasName) {
            return Response.err("Provide exactly one of address or name (got "
                    + (hasAddress && hasName ? "both" : "neither") + ")");
        }
        if (similarity < 0.0 || similarity > 1.0) {
            return Response.err("similarity must be between 0 and 1 (got " + similarity + ")");
        }
        if (significance < 0.0) {
            return Response.err("significance must be >= 0 (got " + significance + ")");
        }
        if (max < 1) {
            return Response.err("max must be at least 1 (got " + max + ")");
        }

        // parseAddress keeps per-thread error state, so it must run on the HTTP
        // worker thread BEFORE entering executeRead (see ServiceUtils.parseAddress).
        Address targetAddr = null;
        if (hasAddress) {
            targetAddr = ServiceUtils.parseAddress(program, address);
            if (targetAddr == null) {
                return Response.err("Cannot parse address '" + address + "': "
                        + ServiceUtils.getLastParseError());
            }
        }
        final Address addr = targetAddr;

        // Function lookups read the program's listing; keep them off the HTTP
        // worker thread like the signature generation below.
        Function func;
        try {
            func = threadingStrategy.executeRead(() -> {
                FunctionManager fman = program.getFunctionManager();
                if (addr != null) {
                    Function f = fman.getFunctionAt(addr);
                    if (f == null) {
                        f = fman.getFunctionContaining(addr);
                    }
                    return f;
                }
                String wanted = name.trim();
                Iterator<Function> iter = fman.getFunctions(true);
                while (iter.hasNext()) {
                    Function f = iter.next();
                    if (f.getName().equals(wanted)) {
                        return f;
                    }
                }
                return null;
            });
        } catch (Exception e) {
            Msg.error(this, "bsim_query_function failed", e);
            return Response.err("bsim_query_function failed: "
                    + (e.getMessage() != null ? e.getMessage() : e.toString()));
        }
        if (func == null) {
            if (addr != null) {
                return Response.err("No function at " + addr + " and no containing function found in "
                        + "program " + program.getName() + " — verify the address is a function entry "
                        + "point or inside a function body");
            }
            return Response.err("No function named '" + name.trim() + "' found: no exact match exists "
                    + "in the program's function manager — list functions to get exact names");
        }

        Address entry = func.getEntryPoint();
        String programMd5 = program.getExecutableMD5();

        BSimServerInfo serverInfo = new BSimServerInfo(dbPath);
        BSimH2FileDataSource existing =
            BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
        GenSignatures gensig = null;
        try (FunctionDatabase db = BSimClientFactory.buildClient(serverInfo, false)) {
            if (!db.initialize()) {
                String errMsg = db.getLastError() != null
                    ? db.getLastError().message : "Unknown error";
                return Response.err("Cannot open BSim database at " + dbPath + ": " + errMsg);
            }
            DatabaseInformation dbInfo = db.getInfo();

            GenSignatures gen = new GenSignatures(false);
            gensig = gen;
            gen.setVectorFactory(db.getLSHVectorFactory());

            // openProgram/scanFunctions read the listing; keep them off the HTTP
            // worker thread (same as bsim_ingest_program).
            threadingStrategy.executeRead(() -> {
                gen.openProgram(program, null, null, null, null, null);
                gen.scanFunctions(Collections.singletonList(func).iterator(), 1, TaskMonitor.DUMMY);
                return 0;
            });

            DescriptionManager manager = gen.getDescriptionManager();
            if (manager.numFunctions() == 0) {
                return Response.err("Function produced no valid BSim signature (too small or no body)");
            }

            QueryNearest query = new QueryNearest();
            query.manage = manager;
            query.max = max;
            query.thresh = similarity;
            query.signifthresh = significance;
            ResponseNearest response = query.execute(db);
            if (response == null) {
                FunctionDatabase.BSimError lastError = db.getLastError();
                String errMsg = lastError != null ? lastError.message : "Unknown query error";
                return Response.err("bsim_query_function failed: " + errMsg);
            }

            List<Map<String, Object>> matches = new ArrayList<>();
            if (response.result != null) {
                int rank = 0;
                for (SimilarityResult sim : response.result) {
                    FunctionDescription base = sim.getBase();
                    if (base == null) {
                        continue;
                    }
                    Iterator<SimilarityNote> noteIter = sim.iterator();
                    while (noteIter.hasNext()) {
                        SimilarityNote note = noteIter.next();
                        FunctionDescription matchDesc = note.getFunctionDescription();
                        ExecutableRecord matchExe = matchDesc.getExecutableRecord();
                        double simScore = note.getSimilarity();
                        rank++;
                        String matchMd5 = matchExe.getMd5();
                        matches.add(JsonHelper.mapOf(
                            "executable", matchExe.getNameExec(),
                            "executable_md5", matchMd5,
                            "architecture", matchExe.getArchitecture(),
                            "function_name", matchDesc.getFunctionName(),
                            "function_address", "0x" + Long.toHexString(matchDesc.getAddress()),
                            "similarity", simScore,
                            "significance", note.getSignificance(),
                            "rank", rank,
                            "confidence", simScore >= 0.99 ? "exact"
                                          : simScore >= 0.8 ? "high"
                                          : simScore >= 0.6 ? "medium" : "low",
                            "same_executable",
                                programMd5 != null && matchMd5 != null && matchMd5.equals(programMd5)));
                    }
                }
            }

            Map<String, Object> out = new LinkedHashMap<>();
            Map<String, Object> queryInfo = new LinkedHashMap<>();
            queryInfo.put("program", program.getName());
            queryInfo.put("function", func.getName());
            queryInfo.put("address", "0x" + Long.toHexString(entry.getOffset()));
            out.put("query", queryInfo);
            out.put("corpus", dbPath);
            out.put("corpus_name", dbInfo.databasename);
            out.put("similarity", similarity);
            out.put("significance", significance);
            out.put("max_matches", max);
            out.put("signed", true);
            out.put("match_count", matches.size());
            out.put("matches", matches);
            if (matches.isEmpty()) {
                out.put("message", "No matches found in the corpus. Try lowering the similarity "
                        + "threshold (currently " + similarity + ") and/or the significance threshold "
                        + "(currently " + significance + ") for small or heavily-optimized functions, "
                        + "or check bsim_corpus_status to confirm the relevant reference builds were "
                        + "ingested.");
            }
            return Response.ok(out);
        } catch (Exception e) {
            Msg.error(this, "bsim_query_function failed", e);
            return Response.err("bsim_query_function failed: "
                    + (e.getMessage() != null ? e.getMessage() : e.toString()));
        } finally {
            if (gensig != null) {
                gensig.dispose();
            }
            if (existing == null) {
                BSimH2FileDataSource bds =
                    BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
                if (bds != null) {
                    bds.dispose();
                }
            }
        }
    }
}
