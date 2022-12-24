/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv;

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.spdx.spdx_to_osv.osvmodel.OsvPackage;
import org.spdx.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * Parses a download location for package names, versions, commits, and OSV ecosystems
 * 
 * @author Gary O'Neall
 *
 */
public class DownloadLocationParser {
    
	static final String MAVEN_PREFIX = "https://search.maven.org/remotecontent";
	static final Pattern MAVEN_PATTERN = Pattern.compile(MAVEN_PREFIX + ".*?filepath=([^?]+)(\\?.+$|$)");
	static final String NPM_PREFIX = "https://www.npmjs.com/package/";
	static final Pattern NPM_PATTERN_W_VERSION = Pattern.compile(NPM_PREFIX + "([@A-Za-z0-9_.-/]+)/v/([A-Za-z0-9_.-]+)$");
	static final Pattern NPM_PATTERN_NO_VERSION = Pattern.compile(NPM_PREFIX + "([@A-Za-z0-9_.-/]+)$");
	
	static final String NUGET_PREFIX = "https://www.nuget.org/api/";
	static final Pattern NUGET_PATTERN = Pattern.compile(NUGET_PREFIX + "v[0-9]+/package/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$");
	
	static final String GITHUB_PREFIX = "https://github.com/";
	static final String GITHUB_SSH_PREFIX = "git@github.com:";
	static final String GITHUB_GIT_PREFIX = "git+";
	static final String GITHUB_VALID_PART = "[A-Za-z0-9_.\\-]";
	static final String GITHUB_ORG_PROJECT = "("+GITHUB_VALID_PART+"+)/("+GITHUB_VALID_PART+"+)";
	static final Pattern GITHUB_GIT_DOWNLOAD_PATTERN = Pattern.compile("git\\+(https://github\\.com/|git@github\\.com:)" + GITHUB_ORG_PROJECT + 
			"(@"+GITHUB_VALID_PART+"+)?(#"+GITHUB_VALID_PART+"+)?");
	static final Pattern GITHUB_PAGE_PATTERN = Pattern.compile(GITHUB_PREFIX + GITHUB_ORG_PROJECT + "$");
	static final Pattern GITHUB_RELEASE_PATTERN = Pattern.compile(GITHUB_PREFIX + GITHUB_ORG_PROJECT + "/releases/tag/([A-Za-z0-9_.-]+)$");
	static final Pattern GITHUB_HTTPS_PATTERN = Pattern.compile(GITHUB_PREFIX + GITHUB_ORG_PROJECT + "\\.git$");
	static final Pattern GITHUB_SSH_PATTERN = Pattern.compile(GITHUB_SSH_PREFIX + GITHUB_ORG_PROJECT + "\\.git$");
	static final Pattern GITHUB_COMMIT_PATTERN = Pattern.compile(GITHUB_PREFIX + GITHUB_ORG_PROJECT + "/tree/([a-f0-9]{40})$");
	static final Pattern GITHUB_TAG_PATTERN = Pattern.compile(GITHUB_PREFIX + GITHUB_ORG_PROJECT + "/tree/([A-Za-z0-9_.-]+)$");
	
    private String downloadLocation;
    Optional<OsvVulnerabilityRequest> osvVulnerabilityRequest;
    
    public DownloadLocationParser(String downloadLocation) {
        this.downloadLocation = downloadLocation;
        osvVulnerabilityRequest = Optional.empty();
        if (Objects.isNull(downloadLocation) || downloadLocation.isEmpty()) {
        	return;
        }
        
        // Maven Central URL
        if (downloadLocation.startsWith(MAVEN_PREFIX)) {
        	parseMaven();
        } else if (downloadLocation.startsWith(NPM_PREFIX)) {
        	parseNpm();
        } else if (downloadLocation.startsWith(NUGET_PREFIX)) {
        	parseNuget();
        } else if (downloadLocation.startsWith(GITHUB_PREFIX) || downloadLocation.startsWith(GITHUB_SSH_PREFIX)
        		|| downloadLocation.startsWith(GITHUB_GIT_PREFIX)) {
        	parseGithub();
        }
    }

    /**
     * Parses Github
	 */
	private void parseGithub() {
		String githubNamePrefix = "github.com/";
		
		Matcher matcher = GITHUB_GIT_DOWNLOAD_PATTERN.matcher(this.downloadLocation);
		if (matcher.matches()) {
			String org = matcher.group(2);
			String pkg = matcher.group(3);
			String version = null;
			if (matcher.group(4) != null && matcher.group(4).startsWith("@")) {
				version = matcher.group(4).substring(1);
			}
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(githubNamePrefix + org + "/" + pkg, null, null), version));
			return;
		}
		
		matcher = GITHUB_HTTPS_PATTERN.matcher(this.downloadLocation);
		//NOTE: This match must be done before GITHUB_PAGE_PATTERN since it will also match
		if (matcher.matches()) {
			String org = matcher.group(1);
			String pkg = matcher.group(2);

			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(githubNamePrefix + org + "/" + pkg, null, null), null));
			return;
		}
		
		matcher = GITHUB_PAGE_PATTERN.matcher(this.downloadLocation);
		if (matcher.matches()) {
			String org = matcher.group(1);
			String pkg = matcher.group(2);
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(githubNamePrefix + org + "/" + pkg, null, null), null));
			return;
		}
		
		matcher = GITHUB_SSH_PATTERN.matcher(this.downloadLocation);
		if (matcher.matches()) {
			String org = matcher.group(1);
			String pkg = matcher.group(2);
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(githubNamePrefix + org + "/" + pkg, null, null), null));
			return;
		}
		
		//NOTE: This match must be before the GITHUB_TAG_PATTERN since the latter will also match commits
		matcher = GITHUB_COMMIT_PATTERN.matcher(this.downloadLocation);
		if (matcher.matches()) {
			String commit = matcher.group(3);
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(commit));
			return;
		}
		
		matcher = GITHUB_RELEASE_PATTERN.matcher(this.downloadLocation);
		if (matcher.matches()) {
			String org = matcher.group(1);
			String pkg = matcher.group(2);
			String version = matcher.group(3);
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(githubNamePrefix + org + "/" + pkg, null, null), version));
			return;
		}
		
		matcher = GITHUB_TAG_PATTERN.matcher(this.downloadLocation);
		if (matcher.matches()) {
			String org = matcher.group(1);
			String pkg = matcher.group(2);
			String version = matcher.group(3);
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(githubNamePrefix + org + "/" + pkg, null, null), version));
			return;
		}
	}

	/**
	 * Parses NuGet
	 */
	private void parseNuget() {
		Matcher matcher = NUGET_PATTERN.matcher(this.downloadLocation);
		if (matcher.matches()) {
			String pkg = matcher.group(1);
			String version = matcher.group(2);
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(pkg, "NuGet", "pkg:nuget/" + pkg + "@" + version), version));
		}
	}

	/**
	 * Parses NPM
	 */
	private void parseNpm() {
		Matcher matcher = NPM_PATTERN_W_VERSION.matcher(downloadLocation);
		//NOTE: We need to test with the version first since the w/out version pattern will also match
		if (matcher.matches()) {
			String pkg = matcher.group(1);
			String version = matcher.group(2);
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(pkg, "npm", "pkg:npm/" + pkg.replaceAll("@", "%40") + "@" + version), version));
		} else {
			matcher = NPM_PATTERN_NO_VERSION.matcher(downloadLocation);
			if (matcher.matches()) {
				String pkg = matcher.group(1);
				this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
						new OsvPackage(pkg, "npm", "pkg:npm/" + pkg.replaceAll("@", "%40")), null));
			}
		}
	}

	/**
	 * Parses Maven Central
	 */
	private void parseMaven() {
		Matcher matcher = MAVEN_PATTERN.matcher(downloadLocation);
		if (matcher.matches()) {
			String filepath = matcher.group(1);
			String[] parts = filepath.split("/");
			if (parts.length < 3) {
				return;
			}
			String version = parts[parts.length-2];
			StringBuilder pkgName = new StringBuilder(parts[0]);
			for (int i = 1; i < parts.length-2; i++) {
				pkgName.append(".");
				pkgName.append(parts[i]);
			}
			this.osvVulnerabilityRequest = Optional.of(new OsvVulnerabilityRequest(
					new OsvPackage(pkgName.toString(), "Maven", "pkg:maven/" + pkgName.toString() + "@" + version), version));
		}
	}

	/**
     * @return the downloadLocation
     */
    public String getDownloadLocation() {
        return downloadLocation;
    }

    /**
     * @return the osvVulnerabilityRequest
     */
    public Optional<OsvVulnerabilityRequest> getOsvVulnerabilityRequest() {
        return osvVulnerabilityRequest;
    }
}
