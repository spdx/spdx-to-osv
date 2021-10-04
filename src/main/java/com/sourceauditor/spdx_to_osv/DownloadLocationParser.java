/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import java.util.Optional;

import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * Parses a download location for package names, versions, commits, and OSV ecosystems
 * 
 * @author Gary O'Neall
 *
 */
public class DownloadLocationParser {
    
    private String downloadLocation;
    Optional<OsvVulnerabilityRequest> packageNameVersion;
    
    public DownloadLocationParser(String downloadLocation) {
        this.downloadLocation = downloadLocation;
        //TODO: Parse the download location
        
    }

    /**
     * @return the downloadLocation
     */
    public String getDownloadLocation() {
        return downloadLocation;
    }

    /**
     * @return the packageNameVersion
     */
    public Optional<OsvVulnerabilityRequest> getPackageNameVersion() {
        return packageNameVersion;
    }
    
    

}
