package com.xebyte.offline;

import com.xebyte.core.MemoryMapService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Graceful-degradation coverage for MemoryMapService. Each endpoint must return a clean
 * "No program loaded" error rather than throw when no binary is loaded.
 */
public class MemoryMapServiceValidationTest extends TestCase {

    private MemoryMapService service;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        service = new MemoryMapService(ServiceFactory.stubProvider(), ts);
    }

    public void testGetMemoryMapDegradesGracefully() {
        Response r = service.getMemoryMap("");
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testCreateOverlayRegionDegradesGracefully() {
        Response r = service.createOverlayRegion("ovl", "0x40000000", "0x08000000", 0x1000L, "");
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testImportSvdDegradesGracefully() {
        Response r = service.importSvd("<device></device>", "", "");
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testImportSvdXorValidatedAfterProgramLookup() {
        // Both svd_content and svd_path set must not change the
        // "no program loaded" failure path -- the xor validation runs
        // only after the program lookup succeeds, so the missing-program
        // error must still short-circuit cleanly.
        Response r = service.importSvd("<device></device>", "/tmp/x.svd", "");
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }
}
