/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv.osvmodel;

/**
 * OSV affect range object as described at https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit
 * 
 * @author Gary O'Neall
 */
public class OsvAffectedRange {
    
    public enum OsvAffectedType {
        UNSPECIFIED,
        GIT,
        SEMVER,
        ECOSYSTEM
    }

    /**
     * Enum: "UNSPECIFIED" "GIT" "SEMVER" "ECOSYSTEM"
     * Required. The type of version information.
     */
    OsvAffectedType type;
    
    /**
     * Required if type is GIT. 
     * The publicly accessible URL of the repo that can be directly passed to clone commands.
     */
    String repo;
    
    /**
     * Strongly recommended. The earliest version/commit where this vulnerability was introduced in. 
     * If not specified, all commits/versions prior to the fixed commit/version are assumed to be affected.
     */
    String introduced;
    
    /**
     * Optional only if introduced is specified. The version/commit that this vulnerability was fixed in. 
     * This must be reachable from the "introduced" version/commit.
     * 
     * If the vulnerability is not fixed, this will be unset.
     */
    String fixed;
    
    /**
     * Required empty constructor
     */
    public OsvAffectedRange() {
        
    }

    /**
     * @return the type
     */
    public OsvAffectedType getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(OsvAffectedType type) {
        this.type = type;
    }

    /**
     * @return the repo
     */
    public String getRepo() {
        return repo;
    }

    /**
     * @param repo the repo to set
     */
    public void setRepo(String repo) {
        this.repo = repo;
    }

    /**
     * @return the introduced
     */
    public String getIntroduced() {
        return introduced;
    }

    /**
     * @param introduced the introduced to set
     */
    public void setIntroduced(String introduced) {
        this.introduced = introduced;
    }

    /**
     * @return the fixed
     */
    public String getFixed() {
        return fixed;
    }

    /**
     * @param fixed the fixed to set
     */
    public void setFixed(String fixed) {
        this.fixed = fixed;
    }
}
