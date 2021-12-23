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

import com.sourceauditor.spdx_to_osv.DownloadLocationParser;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * @author gary
 *
 */
public class DownloadLocationParserTest {

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
	public void testMavenCentral() {
		String url = "https://search.maven.org/remotecontent?filepath=org/spdx/licenseListPublisher/2.2.3/licenseListPublisher-2.2.3-jar-with-dependencies.jar";
		DownloadLocationParser dlp = new DownloadLocationParser(url);
		Optional<OsvVulnerabilityRequest> osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("org.spdx.licenseListPublisher", osv.get().getPackage().getName());
		assertEquals("2.2.3", osv.get().getVersion());
		assertEquals("pkg:maven/org.spdx.licenseListPublisher@2.2.3", osv.get().getPackage().getPurl());
		assertEquals("Maven", osv.get().getPackage().getEcosystem());
	}
	
	@Test
	public void testNpm() {
		String url = "https://www.npmjs.com/package/licensecheck/v/1.3.0";
		DownloadLocationParser dlp = new DownloadLocationParser(url);
		Optional<OsvVulnerabilityRequest> osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("licensecheck", osv.get().getPackage().getName());
		assertEquals("1.3.0", osv.get().getVersion());
		assertEquals("pkg:npm/licensecheck@1.3.0", osv.get().getPackage().getPurl());
		assertEquals("npm", osv.get().getPackage().getEcosystem());
		
		url = "https://www.npmjs.com/package/@angular/cli/v/13.1.2";
		dlp = new DownloadLocationParser(url);
		osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("@angular/cli", osv.get().getPackage().getName());
		assertEquals("13.1.2", osv.get().getVersion());
		assertEquals("pkg:npm/%40angular/cli@13.1.2", osv.get().getPackage().getPurl());
		assertEquals("npm", osv.get().getPackage().getEcosystem());
		
		url = "https://www.npmjs.com/package/@angular/cli";
		dlp = new DownloadLocationParser(url);
		osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("@angular/cli", osv.get().getPackage().getName());
		assertEquals(null, osv.get().getVersion());
		assertEquals("pkg:npm/%40angular/cli", osv.get().getPackage().getPurl());
		assertEquals("npm", osv.get().getPackage().getEcosystem());
		
	}
	
	@Test
	public void testNuGet() {
		String url = "https://www.nuget.org/api/v2/package/Newtonsoft.Json/13.0.1";
		DownloadLocationParser dlp = new DownloadLocationParser(url);
		Optional<OsvVulnerabilityRequest> osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("Newtonsoft.Json", osv.get().getPackage().getName());
		assertEquals("13.0.1", osv.get().getVersion());
		assertEquals("pkg:nuget/Newtonsoft.Json@13.0.1", osv.get().getPackage().getPurl());
		assertEquals("NuGet", osv.get().getPackage().getEcosystem());
	}

	@Test
	public void testGitHub() {
		String url = "https://github.com/spdx/tools-java";
		DownloadLocationParser dlp = new DownloadLocationParser(url);
		Optional<OsvVulnerabilityRequest> osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("tools-java", osv.get().getPackage().getName());
		assertEquals(null, osv.get().getVersion());
		assertEquals("pkg:github/spdx/tools-java", osv.get().getPackage().getPurl());
		assertEquals("OSS-Fuzz", osv.get().getPackage().getEcosystem());
		
		url = "https://github.com/spdx/tools-java/releases/tag/v1.0.3";
		dlp = new DownloadLocationParser(url);
		osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("tools-java", osv.get().getPackage().getName());
		assertEquals("v1.0.3", osv.get().getVersion());
		assertEquals("pkg:github/spdx/tools-java@v1.0.3", osv.get().getPackage().getPurl());
		assertEquals("OSS-Fuzz", osv.get().getPackage().getEcosystem());
		
		url = "https://github.com/spdx/tools-java.git";
		dlp = new DownloadLocationParser(url);
		osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("tools-java", osv.get().getPackage().getName());
		assertEquals(null, osv.get().getVersion());
		assertEquals("pkg:github/spdx/tools-java", osv.get().getPackage().getPurl());
		assertEquals("OSS-Fuzz", osv.get().getPackage().getEcosystem());
		
		url = "git@github.com:spdx/tools-java.git";
		dlp = new DownloadLocationParser(url);
		osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("tools-java", osv.get().getPackage().getName());
		assertEquals(null, osv.get().getVersion());
		assertEquals("pkg:github/spdx/tools-java", osv.get().getPackage().getPurl());
		assertEquals("OSS-Fuzz", osv.get().getPackage().getEcosystem());
		
		url = "https://github.com/spdx/tools-java/tree/876c0f1ad03210629cf940505b296e242da97b8e";
		dlp = new DownloadLocationParser(url);
		osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("876c0f1ad03210629cf940505b296e242da97b8e", osv.get().getCommit());
		
		url = "https://github.com/spdx/tools-java/tree/v1.0.3";
		dlp = new DownloadLocationParser(url);
		osv = dlp.getOsvVulnerabilityRequest();
		assertTrue(osv.isPresent());
		assertEquals("tools-java", osv.get().getPackage().getName());
		assertEquals("v1.0.3", osv.get().getVersion());
		assertEquals("pkg:github/spdx/tools-java@v1.0.3", osv.get().getPackage().getPurl());
		assertEquals("OSS-Fuzz", osv.get().getPackage().getEcosystem());
	}
}
