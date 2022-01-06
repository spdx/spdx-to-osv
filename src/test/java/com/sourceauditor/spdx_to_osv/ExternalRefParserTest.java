/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import static org.junit.Assert.*;

import java.io.IOException;
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

import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

import us.springett.parsers.cpe.values.Part;

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
     * @throws SwhException 
     * @throws IOException 
     */
    @Test
    public void testExternalRefParser() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
        ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                new ReferenceType("https://my/eternal/ref"), "mylocator", "This is a test");
        ExternalRefParser erp = new ExternalRefParser(er);
        assertTrue(er.equivalent(erp.getExternalRef()));
    }
    
    @Test
    public void testCpe22()  throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
        ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.SECURITY, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("cpe22Type"), 
                "cpe:/o:canonical:ubuntu_linux:10.04:-:lts:en", null);
        ExternalRefParser erp = new ExternalRefParser(er);
        assertEquals(Optional.of(Part.OPERATING_SYSTEM), erp.getCpePart());
        assertEquals(Optional.of("canonical"), erp.getVendor());
        Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
        assertTrue(ovr.isPresent());
        assertEquals("ubuntu_linux", ovr.get().getPackage().getName());
        assertEquals("10.04", ovr.get().getVersion());
        assertEquals(Optional.of("-"), erp.getUpdate());
        assertEquals(Optional.of("lts"), erp.getEdition());
        assertEquals(Optional.of("en"), erp.getLanguage());
    }

    @Test
    public void testCpe23()  throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
        ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.SECURITY, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("cpe23Type"), 
                "cpe:2.3:o:canonical:ubuntu_linux:10.04::lts:en:*:*:*:*", null);
        ExternalRefParser erp = new ExternalRefParser(er);
        assertEquals(Optional.of(Part.OPERATING_SYSTEM), erp.getCpePart());
        assertEquals(Optional.of("canonical"), erp.getVendor());
        Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
        assertTrue(ovr.isPresent());
        assertEquals("ubuntu_linux", ovr.get().getPackage().getName());
        assertEquals("10.04", ovr.get().getVersion());
        assertEquals("*", erp.getUpdate().get());
        assertEquals(Optional.of("lts"), erp.getEdition());
        assertEquals(Optional.of("en"), erp.getLanguage());
    }
    
    @Test
    public void testSwh() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
/* TODO: Uncomment this out after updating the SPDX tools version
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PERSISTENT_ID, 

                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("swh"), 
                "swh:1:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
        assertTrue(ovr.isPresent());
        assertEquals("22ece559cc7cc2364edc5e5593d63ae8bd229f9f", ovr.get().getCommit());
         */
    }
    
    @Test
    public void testPurlGithub() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
        assertTrue(ovr.isPresent());
        assertEquals("244fd47e07d1004f0aed9c", ovr.get().getCommit());
    }
    
    @Test
    public void testPurlBitbucket() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
        assertTrue(ovr.isPresent());
        assertEquals("244fd47e07d1014f0aed9c", ovr.get().getCommit());
    }
    
    @Test
    public void testPurlDeb() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("curl", ovr.get().getPackage().getName());
    	assertEquals("7.50.3-1", ovr.get().getVersion());
    	assertEquals("pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie", ovr.get().getPackage().getPurl());
    }
    
    @Test
    public void testPurlDocker() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
        assertTrue(ovr.isPresent());
        assertEquals("244fd47e07d1004f0aed9c", ovr.get().getCommit());
        
        er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io", null);
    	erp = new ExternalRefParser(er);
    	ovr = erp.osvVulnerabilityRequest();
        assertTrue(ovr.isPresent());
        assertEquals("244fd47e07d1004f0aed9c", ovr.get().getCommit());
    }
    
    @Test
    public void testPurlGem() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:gem/jruby-launcher@1.1.2?platform=java", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("jruby-launcher", ovr.get().getPackage().getName());
    	assertEquals("1.1.2", ovr.get().getVersion());
    	assertEquals("pkg:gem/jruby-launcher@1.1.2?platform=java", ovr.get().getPackage().getPurl());
    	assertEquals("OSS-Fuzz", ovr.get().getPackage().getEcosystem());
        
        er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:gem/ruby-advisory-db-check@0.12.4", null);
    	erp = new ExternalRefParser(er);
    	ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("ruby-advisory-db-check", ovr.get().getPackage().getName());
    	assertEquals("0.12.4", ovr.get().getVersion());
    	assertEquals("pkg:gem/ruby-advisory-db-check@0.12.4", ovr.get().getPackage().getPurl());
    	assertEquals("OSS-Fuzz", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testPurlGolang() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:golang/google.golang.org/genproto#googleapis/api/annotations", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("genproto", ovr.get().getPackage().getName());
    	assertEquals("pkg:golang/google.golang.org/genproto#googleapis/api/annotations", ovr.get().getPackage().getPurl());
    	assertEquals("Go", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testPurlMaven() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources", null);
    	ExternalRefParser erp = new ExternalRefParser(er, false);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("batik-anim", ovr.get().getPackage().getName());
    	assertEquals("1.9.1", ovr.get().getVersion());
    	assertEquals("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources", ovr.get().getPackage().getPurl());
    	assertEquals("Maven", ovr.get().getPackage().getEcosystem());
        
        er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io/release", null);
    	erp = new ExternalRefParser(er, true);
    	ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("org.apache.xmlgraphics:batik-anim", ovr.get().getPackage().getName());
    	assertEquals("1.9.1", ovr.get().getVersion());
    	assertEquals("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io/release", ovr.get().getPackage().getPurl());
    	assertEquals("Maven", ovr.get().getPackage().getEcosystem());
    	erp = new ExternalRefParser(er, false);
    	ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("batik-anim", ovr.get().getPackage().getName());
    	assertEquals("1.9.1", ovr.get().getVersion());
    	assertEquals("pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io/release", ovr.get().getPackage().getPurl());
    	assertEquals("Maven", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testPurlNpm() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:npm/%40angular/animation@12.3.1", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("animation", ovr.get().getPackage().getName());
    	assertEquals("12.3.1", ovr.get().getVersion());
    	assertEquals("pkg:npm/%40angular/animation@12.3.1", ovr.get().getPackage().getPurl());
    	assertEquals("npm", ovr.get().getPackage().getEcosystem());
        
        er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:npm/foobar@12.3.1", null);
    	erp = new ExternalRefParser(er);
    	ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("foobar", ovr.get().getPackage().getName());
    	assertEquals("12.3.1", ovr.get().getVersion());
    	assertEquals("pkg:npm/foobar@12.3.1", ovr.get().getPackage().getPurl());
    	assertEquals("npm", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testPurlNuget() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:nuget/EnterpriseLibrary.Common@6.0.1304", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("EnterpriseLibrary.Common", ovr.get().getPackage().getName());
    	assertEquals("6.0.1304", ovr.get().getVersion());
    	assertEquals("pkg:nuget/EnterpriseLibrary.Common@6.0.1304", ovr.get().getPackage().getPurl());
    	assertEquals("NuGet", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testPyPi() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:pypi/django@1.11.1", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("django", ovr.get().getPackage().getName());
    	assertEquals("1.11.1", ovr.get().getVersion());
    	assertEquals("pkg:pypi/django@1.11.1", ovr.get().getPackage().getPurl());
    	assertEquals("PyPI", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testPurlRpm() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("curl", ovr.get().getPackage().getName());
    	assertEquals("7.50.3-1.fc25", ovr.get().getVersion());
    	assertEquals("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25", ovr.get().getPackage().getPurl());
    	assertEquals("OSS-Fuzz", ovr.get().getPackage().getEcosystem());
        
        er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
                "pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed", null);
    	erp = new ExternalRefParser(er);
    	ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("curl", ovr.get().getPackage().getName());
    	assertEquals("7.56.1-1.1.", ovr.get().getVersion());
    	assertEquals("pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed", ovr.get().getPackage().getPurl());
    	assertEquals("OSS-Fuzz", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testMaven() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("maven-central"), 
                "org.spdx:tools-java:2.2.2", null);
    	ExternalRefParser erp = new ExternalRefParser(er, false);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("tools-java", ovr.get().getPackage().getName());
    	assertEquals("2.2.2", ovr.get().getVersion());
    	assertEquals("pkg:maven/org.spdx/tools-java@2.2.2", ovr.get().getPackage().getPurl());
    	assertEquals("Maven", ovr.get().getPackage().getEcosystem());
    	
    	er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("maven-central"), 
                "org.spdx:tools-java:2.2.2", null);
    	erp = new ExternalRefParser(er, true);
    	ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("org.spdx:tools-java", ovr.get().getPackage().getName());
    	assertEquals("2.2.2", ovr.get().getVersion());
    	assertEquals("pkg:maven/org.spdx/tools-java@2.2.2", ovr.get().getPackage().getPurl());
    	
    	er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("maven-central"), 
                "org.spdx:tools-java", null);
    	erp = new ExternalRefParser(er, true);
    	ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("org.spdx:tools-java", ovr.get().getPackage().getName());
    	assertTrue(ovr.get().getVersion() == null);
    	assertEquals("pkg:maven/org.spdx/tools-java", ovr.get().getPackage().getPurl());
    }
    
    @Test
    public void testNpm() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("npm"), 
                "http-server@0.3.0", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("http-server", ovr.get().getPackage().getName());
    	assertEquals("0.3.0", ovr.get().getVersion());
    	assertEquals("pkg:npm/http-server@0.3.0", ovr.get().getPackage().getPurl());
    	assertEquals("npm", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testNuget() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("nuget"), 
                "Microsoft.AspNet.MVC/5.0.0", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("Microsoft.AspNet.MVC", ovr.get().getPackage().getName());
    	assertEquals("5.0.0", ovr.get().getVersion());
    	assertEquals("pkg:nuget/Microsoft.AspNet.MVC@5.0.0", ovr.get().getPackage().getPurl());
    	assertEquals("NuGet", ovr.get().getPackage().getEcosystem());
    }
    
    @Test
    public void testBower() throws InvalidSPDXAnalysisException, InvalidExternalRefPattern, IOException, SwhException {
    	ExternalRef er = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("bower"), 
                "modernizr#2.6.2", null);
    	ExternalRefParser erp = new ExternalRefParser(er);
    	Optional<OsvVulnerabilityRequest> ovr = erp.osvVulnerabilityRequest();
    	assertTrue(ovr.isPresent());
    	assertEquals("modernizr", ovr.get().getPackage().getName());
    	assertEquals("2.6.2", ovr.get().getVersion());
    	assertEquals("OSS-Fuzz", ovr.get().getPackage().getEcosystem());
    }
}
