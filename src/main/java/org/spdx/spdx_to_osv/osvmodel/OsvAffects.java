/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv.osvmodel;

import java.util.List;

/**
 * OSV affects object as described at https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit
 * 
 * @author Gary O'Neall
 */
@Deprecated
public class OsvAffects {
    
    /**
     * Required (at least one entry). The commit/version ranges that contain this vulnerability.
     * 
     * When provided, OSV will attempt to detect and append additional ranges 
     * that may be affected as well (e.g. cherry-picks to other branches).
     */
    List<OsvAffectedRange> ranges;
    
    /**
     * Optional. List of affected versions. This should match tag names in the upstream repository. 
     * OSV will populate or add to this automatically based on the provided commit ranges.
     */
    List<String> versions;
    
    /**
     * Required empty constructor
     */
    public OsvAffects() {
        
    }

    /**
     * @return the ranges
     */
    public List<OsvAffectedRange> getRanges() {
        return ranges;
    }

    /**
     * @param ranges the ranges to set
     */
    public void setRanges(List<OsvAffectedRange> ranges) {
        this.ranges = ranges;
    }

    /**
     * @return the versions
     */
    public List<String> getVersions() {
        return versions;
    }

    /**
     * @param versions the versions to set
     */
    public void setVersions(List<String> versions) {
        this.versions = versions;
    }

}
