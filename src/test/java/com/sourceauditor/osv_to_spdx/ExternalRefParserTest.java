/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.osv_to_spdx;

import static org.junit.Assert.*;

import java.util.Optional;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.ReferenceType;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.SpdxPackageVerificationCode;
import org.spdx.library.model.enumerations.ReferenceCategory;
import org.spdx.library.model.license.SpdxNoneLicense;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.storage.IModelStore;
import org.spdx.storage.simple.InMemSpdxStore;

import com.sourceauditor.spdx_to_osv.ExternalRefParser;
import com.sourceauditor.spdx_to_osv.InvalidExternalRefPattern;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * @author Gary O'Neall
 *
 */
public class ExternalRefParserTest {
    
    static final String DOCUMENT_URI = "https://this.is.a.document/uri";
    SpdxPackage spdxPackage;
    IModelStore modelStore;
    ModelCopyManager copyManager;
    

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        modelStore = new InMemSpdxStore();
        copyManager = new ModelCopyManager();
        spdxPackage = SpdxModelFactory.createSpdxDocument(modelStore, DOCUMENT_URI, copyManager)
                .createPackage("SPDXRef-package", "Package Name", new SpdxNoneLicense(), 
                        "NONE", new SpdxNoneLicense())
                .setPackageVerificationCode(new SpdxPackageVerificationCode())
                .build();
    }

    /**
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test method for {@link com.sourceauditor.spdx_to_osv.ExternalRefParser#ExternalRefParser(org.spdx.library.model.ExternalRef)}.
     * @throws InvalidSPDXAnalysisException 
     * @throws InvalidExternalRefPattern 
     */
    @Test
    public void testExternalRefParser() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern {
        ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                new ReferenceType("https://my/eternal/ref"), "mylocator", "This is a test");
        ExternalRefParser erp = new ExternalRefParser(er);
        assertTrue(er.equivalent(erp.getExternalRef()));
    }
    
    @Test
    public void testCpe22()  throws InvalidSPDXAnalysisException, InvalidExternalRefPattern {
        ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.SECURITY, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("cpe22Type"), 
                "cpe:/o:canonical:ubuntu_linux:10.04:-:lts:en", null);
        ExternalRefParser erp = new ExternalRefParser(er);
        assertEquals(Optional.of(ExternalRefParser.CPE_PART.OPERATING_SYSTEM), erp.getCpePart());
        assertEquals(Optional.of("canonical"), erp.getVendor());
        Optional<OsvVulnerabilityRequest> ovr = erp.getPackageNameVersion();
        assertTrue(ovr.isPresent());
        assertEquals("ubuntu_linux", ovr.get().getPackage().getName());
        assertEquals("10.04", ovr.get().getVersion());
        assertEquals(Optional.of("-"), erp.getUpdate());
        assertEquals(Optional.of("lts"), erp.getEdition());
        assertEquals(Optional.of("en"), erp.getLanguage());
    }

    @Test
    public void testCpe23()  throws InvalidSPDXAnalysisException, InvalidExternalRefPattern {
        ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.SECURITY, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("cpe23Type"), 
                "cpe:2.3:o:canonical:ubuntu_linux:10.04:­:lts:*:*:*:*:*", null);
        ExternalRefParser erp = new ExternalRefParser(er);
        assertEquals(Optional.of(ExternalRefParser.CPE_PART.OPERATING_SYSTEM), erp.getCpePart());
        assertEquals(Optional.of("canonical"), erp.getVendor());
        Optional<OsvVulnerabilityRequest> ovr = erp.getPackageNameVersion();
        assertTrue(ovr.isPresent());
        assertEquals("ubuntu_linux", ovr.get().getPackage().getName());
        assertEquals("10.04", ovr.get().getVersion());
        assertFalse(erp.getUpdate().isPresent());
        assertEquals(Optional.of("lts"), erp.getEdition());
        assertEquals(Optional.of("en"), erp.getLanguage());
    }

    
}
