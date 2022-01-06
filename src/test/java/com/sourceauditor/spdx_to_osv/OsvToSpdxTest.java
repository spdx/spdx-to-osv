/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.Relationship;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.enumerations.ReferenceCategory;
import org.spdx.library.model.enumerations.RelationshipType;
import org.spdx.library.model.license.SpdxNoAssertionLicense;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.simple.InMemSpdxStore;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvAffected;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerability;

/**
 * @author gary
 *
 */
public class OsvToSpdxTest {
	
	static final String SPREADSHEET_FILE = "test-resources" + File.separator + "spdx-test-externalref.xlsx";
	static final String JSON_FILE = "test-resources" + File.separator + "spdx-test-externalref.json";
	static final String TAGVALUE_FILE = "test-resources" + File.separator + "spdx-test-externalref.spdx";
	static final String RDFXML_FILE = "test-resources" + File.separator + "spdx-test-externalref.rdf.xml";
	
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
	public void testNpmExternalRef() throws InvalidSPDXAnalysisException, SpdxToOsvException, IOException {
		InMemSpdxStore modelStore = new InMemSpdxStore();
		ModelCopyManager copyManager = new ModelCopyManager();
		String documentUri = "https://org.spdx.documents/this/is/a/test";
		SpdxDocument doc = SpdxModelFactory.createSpdxDocument(modelStore, documentUri, copyManager);
		ExternalRef externalRef = doc.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
				ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("npm"), 
				"tinymce@4.9.11", null);
		SpdxPackage tinymcePackage = doc.createPackage(modelStore.getNextId(IdType.SpdxId, documentUri), 
				"tinymce", new SpdxNoAssertionLicense(), "NOASSERTION", new SpdxNoAssertionLicense())
				.setFilesAnalyzed(false)
				.addExternalRef(externalRef)
				.build();
		Relationship describesRelationship = doc.createRelationship(tinymcePackage, RelationshipType.DESCRIBES, null);
		doc.addRelationship(describesRelationship);
		StringWriter writer = new StringWriter();
		Main.spdxToOsv(modelStore, documentUri, writer);
		String resultStr = writer.toString();
		Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
		List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
		assertTrue(result.size() > 0);
		assertTrue(result.get(0).getAffected().size() > 0);
        assertEquals("tinymce", result.get(0).getAffected().get(0).getOsvPackage().getName());
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
	public void testMavenExternalRef() throws InvalidSPDXAnalysisException, SpdxToOsvException, IOException {
		InMemSpdxStore modelStore = new InMemSpdxStore();
		ModelCopyManager copyManager = new ModelCopyManager();
		String documentUri = "https://org.spdx.documents/this/is/a/test";
		SpdxDocument doc = SpdxModelFactory.createSpdxDocument(modelStore, documentUri, copyManager);
		ExternalRef externalRef = doc.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
				ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("maven-central"), 
				"org.webjars.npm:xlsx:0.16.6", null);
		SpdxPackage xlsxPackage = doc.createPackage(modelStore.getNextId(IdType.SpdxId, documentUri), 
				"xlsx", new SpdxNoAssertionLicense(), "NOASSERTION", new SpdxNoAssertionLicense())
				.setFilesAnalyzed(false)
				.addExternalRef(externalRef)
				.build();
		Relationship describesRelationship = doc.createRelationship(xlsxPackage, RelationshipType.DESCRIBES, null);
		doc.addRelationship(describesRelationship);
		StringWriter writer = new StringWriter();
		Main.spdxToOsv(modelStore, documentUri, writer);
		String resultStr = writer.toString();
		Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
		List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
		assertTrue(result.size() > 0);
		assertTrue(result.get(0).getAffected().size() > 0);
        assertEquals("org.webjars.npm:xlsx", result.get(0).getAffected().get(0).getOsvPackage().getName());
	}
	
	@Test
	public void testPurlExternalRef() throws InvalidSPDXAnalysisException, SpdxToOsvException, IOException {
		InMemSpdxStore modelStore = new InMemSpdxStore();
		ModelCopyManager copyManager = new ModelCopyManager();
		String documentUri = "https://org.spdx.documents/this/is/a/test";
		SpdxDocument doc = SpdxModelFactory.createSpdxDocument(modelStore, documentUri, copyManager);
		ExternalRef externalRef = doc.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
				ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
				"pkg:maven/org.webjars.npm/xlsx@0.16.6", null);
		SpdxPackage xlsxPackage = doc.createPackage(modelStore.getNextId(IdType.SpdxId, documentUri), 
				"xlsx", new SpdxNoAssertionLicense(), "NOASSERTION", new SpdxNoAssertionLicense())
				.setFilesAnalyzed(false)
				.addExternalRef(externalRef)
				.build();
		Relationship describesRelationship = doc.createRelationship(xlsxPackage, RelationshipType.DESCRIBES, null);
		doc.addRelationship(describesRelationship);
		StringWriter writer = new StringWriter();
		Main.spdxToOsv(modelStore, documentUri, writer);
		String resultStr = writer.toString();
		Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
		List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
		assertTrue(result.size() > 0);
		assertTrue(result.get(0).getAffected().size() > 0);
        assertEquals("org.webjars.npm:xlsx", result.get(0).getAffected().get(0).getOsvPackage().getName());
	}
	
	@Test
	public void testDuplicateDownloadExternalRef()  throws InvalidSPDXAnalysisException, SpdxToOsvException, IOException {
		InMemSpdxStore modelStore = new InMemSpdxStore();
		ModelCopyManager copyManager = new ModelCopyManager();
		String documentUri = "https://org.spdx.documents/this/is/a/test";
		SpdxDocument doc = SpdxModelFactory.createSpdxDocument(modelStore, documentUri, copyManager);
		ExternalRef externalRef = doc.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
				ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("npm"), 
				"tinymce@4.9.11", null);
		SpdxPackage tinymcePackage = doc.createPackage(modelStore.getNextId(IdType.SpdxId, documentUri), 
				"tinymce", new SpdxNoAssertionLicense(), "NOASSERTION", new SpdxNoAssertionLicense())
				.setFilesAnalyzed(false)
				.addExternalRef(externalRef)
				.build();
		Relationship describesRelationship = doc.createRelationship(tinymcePackage, RelationshipType.DESCRIBES, null);
		doc.addRelationship(describesRelationship);
		StringWriter writer = new StringWriter();
		Main.spdxToOsv(modelStore, documentUri, writer);
		String resultStr = writer.toString();
		Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
		List<OsvVulnerability> singleResult = gson.fromJson(resultStr, listType);
		assertTrue(singleResult.size() > 0);
		assertTrue(singleResult.get(0).getAffected().size() > 0);
        assertEquals("tinymce", singleResult.get(0).getAffected().get(0).getOsvPackage().getName());
        
        // Add a download location which matches the NPM - the results should be the same, not duplicated
        String downloadLocation = "https://www.npmjs.com/package/tinymce/v/4.9.11";
        tinymcePackage.setDownloadLocation(downloadLocation);
        writer = new StringWriter();
		Main.spdxToOsv(modelStore, documentUri, writer);
		resultStr = writer.toString();
		List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
		assertEquals(singleResult.size(), result.size());
	}
	
	@Test
	public void testJsonFormat()  throws IOException, SpdxToOsvException {
		File spdxFile = new File(JSON_FILE);
		Path outputDir = Files.createTempDirectory("osv-to-spdx-test");
		File outputFile = outputDir.resolve("output.json").toFile();
		try {
			Main.spdxToOsv(spdxFile, outputFile);
			String resultStr = Files.readString(outputFile.toPath());
			Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
			List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
			boolean foundTinyMce = false;
			boolean foundXlsx = false;
			boolean foundJinja = false;
			for (OsvVulnerability ov:result) {
				for (OsvAffected affected:ov.getAffected()) {
					if ("tinymce".equals(affected.getOsvPackage().getName())) {
						foundTinyMce = true;
					}
					if ("org.webjars.npm:xlsx".equals(affected.getOsvPackage().getName())) {
						foundXlsx = true;
					}
					if ("harfbuzz".equals(affected.getOsvPackage().getName())) {
						foundJinja = true;
					}
				}
			}
			assertTrue(foundTinyMce);
			assertTrue(foundXlsx);
			assertTrue(foundJinja);
		} finally {
			outputDir.toFile().deleteOnExit();
			outputDir.forEach(filePath -> {
				filePath.toFile().deleteOnExit();
			});
		}
	}
	
	@Test
	public void testTagValueFormat()  throws IOException, SpdxToOsvException {
		File spdxFile = new File(TAGVALUE_FILE);
		Path outputDir = Files.createTempDirectory("osv-to-spdx-test");
		File outputFile = outputDir.resolve("output.json").toFile();
		try {
			Main.spdxToOsv(spdxFile, outputFile);
			String resultStr = Files.readString(outputFile.toPath());
			Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
			List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
			boolean foundTinyMce = false;
			boolean foundXlsx = false;
			boolean foundJinja = false;
			for (OsvVulnerability ov:result) {
				for (OsvAffected affected:ov.getAffected()) {
					if ("tinymce".equals(affected.getOsvPackage().getName())) {
						foundTinyMce = true;
					}
					if ("org.webjars.npm:xlsx".equals(affected.getOsvPackage().getName())) {
						foundXlsx = true;
					}
					if ("harfbuzz".equals(affected.getOsvPackage().getName())) {
						foundJinja = true;
					}
				}
			}
			assertTrue(foundTinyMce);
			assertTrue(foundXlsx);
			assertTrue(foundJinja);
		} finally {
			outputDir.toFile().deleteOnExit();
			outputDir.forEach(filePath -> {
				filePath.toFile().deleteOnExit();
			});
		}
	}
	
	@Test
	public void testRdfXmlFormat()  throws IOException, SpdxToOsvException {
		File spdxFile = new File(RDFXML_FILE);
		Path outputDir = Files.createTempDirectory("osv-to-spdx-test");
		File outputFile = outputDir.resolve("output.json").toFile();
		try {
			Main.spdxToOsv(spdxFile, outputFile);
			String resultStr = Files.readString(outputFile.toPath());
			Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
			List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
			boolean foundTinyMce = false;
			boolean foundXlsx = false;
			boolean foundJinja = false;
			for (OsvVulnerability ov:result) {
				for (OsvAffected affected:ov.getAffected()) {
					if ("tinymce".equals(affected.getOsvPackage().getName())) {
						foundTinyMce = true;
					}
					if ("org.webjars.npm:xlsx".equals(affected.getOsvPackage().getName())) {
						foundXlsx = true;
					}
					if ("harfbuzz".equals(affected.getOsvPackage().getName())) {
						foundJinja = true;
					}
				}
			}
			assertTrue(foundTinyMce);
			assertTrue(foundXlsx);
			assertTrue(foundJinja);
		} finally {
			outputDir.toFile().deleteOnExit();
			outputDir.forEach(filePath -> {
				filePath.toFile().deleteOnExit();
			});
		}
	}
	
	@Test
	public void testXslxFormat() throws IOException, SpdxToOsvException {
		File spdxFile = new File(SPREADSHEET_FILE);
		Path outputDir = Files.createTempDirectory("osv-to-spdx-test");
		File outputFile = outputDir.resolve("output.json").toFile();
		try {
			Main.spdxToOsv(spdxFile, outputFile);
			String resultStr = Files.readString(outputFile.toPath());
			Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
			List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
			boolean foundTinyMce = false;
			boolean foundXlsx = false;
			boolean foundJinja = false;
			for (OsvVulnerability ov:result) {
				for (OsvAffected affected:ov.getAffected()) {
					if ("tinymce".equals(affected.getOsvPackage().getName())) {
						foundTinyMce = true;
					}
					if ("org.webjars.npm:xlsx".equals(affected.getOsvPackage().getName())) {
						foundXlsx = true;
					}
					if ("harfbuzz".equals(affected.getOsvPackage().getName())) {
						foundJinja = true;
					}
				}
			}
			assertTrue(foundTinyMce);
			assertTrue(foundXlsx);
			assertTrue(foundJinja);
		} finally {
			outputDir.toFile().deleteOnExit();
			outputDir.forEach(filePath -> {
				filePath.toFile().deleteOnExit();
			});
		}
	}
	
	@Test
	public void testNpmExternalRefLog4j() throws InvalidSPDXAnalysisException, SpdxToOsvException, IOException {
		InMemSpdxStore modelStore = new InMemSpdxStore();
		ModelCopyManager copyManager = new ModelCopyManager();
		String documentUri = "https://org.spdx.documents/this/is/a/test";
		SpdxDocument doc = SpdxModelFactory.createSpdxDocument(modelStore, documentUri, copyManager);
		ExternalRef externalRef = doc.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
				ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("maven-central"), 
				"org.apache.logging.log4j:log4j-core:2.15.0", null);
		SpdxPackage log4jPackage = doc.createPackage(modelStore.getNextId(IdType.SpdxId, documentUri), 
				"log4j-core", new SpdxNoAssertionLicense(), "NOASSERTION", new SpdxNoAssertionLicense())
				.setFilesAnalyzed(false)
				.addExternalRef(externalRef)
				.build();
		Relationship describesRelationship = doc.createRelationship(log4jPackage, RelationshipType.DESCRIBES, null);
		doc.addRelationship(describesRelationship);
		StringWriter writer = new StringWriter();
		Main.spdxToOsv(modelStore, documentUri, writer);
		String resultStr = writer.toString();
		Type listType = new TypeToken<List<OsvVulnerability>>(){}.getType();
		List<OsvVulnerability> result = gson.fromJson(resultStr, listType);
		assertTrue(result.size() > 0);
		boolean foundPkg = false;
		for (OsvVulnerability vuln:result) {
			for (OsvAffected affected:vuln.getAffected()) {
				if ("org.apache.logging.log4j:log4j-core".equals(affected.getOsvPackage().getName())) {
					foundPkg = true;
					break;
				}
				if (foundPkg) {
					break;
				}
			}
		}
		assertTrue(foundPkg);
	}
}
