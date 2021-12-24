/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Type;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.Relationship;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.enumerations.RelationshipType;
import org.spdx.library.model.license.SpdxNoAssertionLicense;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.simple.InMemSpdxStore;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvPackage;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerability;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * @author gary
 *
 */
public class OsvToSpdxTest {
	
	static Gson gson = new GsonBuilder().setPrettyPrinting().create();

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

	@Test
	public void testNpmExternalRef() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testDownloadLocationGitSha1() throws InvalidSPDXAnalysisException, SpdxToOsvException, IOException {
		String downloadLocation = "https://github.com/pallets/jinja/tree/6879efc2c1596d11a6a6ad296f80063b558d5e0f";
		InMemSpdxStore modelStore = new InMemSpdxStore();
		ModelCopyManager copyManager = new ModelCopyManager();
		String documentUri = "https://org.spdx.documents/this/is/a/test";
		SpdxDocument doc = SpdxModelFactory.createSpdxDocument(modelStore, documentUri, copyManager);
		SpdxPackage jinjaPackage = doc.createPackage(modelStore.getNextId(IdType.SpdxId, documentUri), 
				"Jinja", new SpdxNoAssertionLicense(), "NOASSERTION", new SpdxNoAssertionLicense())
				.setDownloadLocation(downloadLocation)
				.setFilesAnalyzed(false)
				.build();
		Relationship describesRelationship = doc.createRelationship(jinjaPackage, RelationshipType.DESCRIBES, null);
		doc.addRelationship(describesRelationship);
		StringWriter writer = new StringWriter();
		Main.spdxToOsv(modelStore, documentUri, writer);
		String resultStr = writer.toString();
		Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
		List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
		assertEquals(1, result.size());
		assertTrue(result.get(0).getAffected().size() > 0);
        assertEquals("harfbuzz", result.get(0).getAffected().get(0).getOsvPackage().getName());
	}
	
	@Test
	public void testMavenExternalRef() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testDuplicateDownloadExternalRef() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testMultipleDownload() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testMultipleExternalRef() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testJsonFormat() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testTagValueFormat() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testRdfXmlFormat() {
		fail("Not yet implemented");
	}
	
	@Test
	public void testXslxFormat() {
		fail("Not yet implemented");
	}
}
