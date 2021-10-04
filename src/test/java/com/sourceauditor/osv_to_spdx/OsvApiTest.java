/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.osv_to_spdx;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.sourceauditor.spdx_to_osv.OsvApi;
import com.sourceauditor.spdx_to_osv.SpdxToOsvException;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvPackage;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerability;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * @author Gary O'Neall
 *
 */
public class OsvApiTest {

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
    }

    /**
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test method for {@link com.sourceauditor.spdx_to_osv.OsvApi#queryVulnerabilities(com.sourceauditor.spdx_to_osv.osvmodel.OsvPackageAndVersion)}.
     * @throws SpdxToOsvException 
     * @throws IOException 
     */
    @Test
    public void testQueryVulnerabilitiesSuccess() throws IOException, SpdxToOsvException {
        // Commit
        OsvVulnerabilityRequest request = new OsvVulnerabilityRequest("6879efc2c1596d11a6a6ad296f80063b558d5e0f");  // commit taken from the example provided for the OSV API
        List<OsvVulnerability> result = OsvApi.getInstance().queryVulnerabilities(request);
        assertTrue(result.size() > 0);
        assertEquals("harfbuzz", result.get(0).getOsvPackage().getName());
        // Package and Version
        request = new OsvVulnerabilityRequest(new OsvPackage("jinja2", "PyPI", null), "2.4.1");
        result = OsvApi.getInstance().queryVulnerabilities(request);
        assertTrue(result.size() > 0);
        assertEquals("jinja2", result.get(0).getOsvPackage().getName());
        // not in database
        request = new OsvVulnerabilityRequest(new OsvPackage("tools-java", "OSV-Fuzz", null), "1.0.1");
        result = OsvApi.getInstance().queryVulnerabilities(request);
        assertEquals(0, result.size());
    }

}
