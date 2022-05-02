/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv.osvmodel;

import java.util.Objects;

import javax.annotation.Nullable;

/**
 * OSV Package as described in https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit
 * @author Gary O'Neall
 *
 */
public class OsvPackage {
    
    /**
     * Required. Name of the package. Should match the name used in the package ecosystem (e.g. the npm package name). 
     * For C/C++ projects integrated in OSS-Fuzz, this is the name used for the integration.
     */
    private String name;
    
    /**
     * Required. The ecosystem for this package. 
     * For vulnerabilities from OSS-Fuzz that do not have a package ecosystem (e.g. C/C++ packages), this is "OSS-Fuzz". 
     * Other valid values are:
     * 
     * - "Go" for Go modules.
     * - "PyPI" for Python packages.
     * - "NPM" for NPM packages.
     */
    private String ecosystem;
    
    /**
     * Optional. The package URL for this package.
     */
    private String purl;
    
    /**
     * Required empty constructor
     */
    public OsvPackage() {
        
    }

    /**
     * @param name Package name
     * @param ecosystem Ecosystem supported by OSV
     * @param purl Optional Package URL
     */
    public OsvPackage(String name, String ecosystem, @Nullable String purl) {
        Objects.requireNonNull(name, "Package name can not be null");
        this.name = name;
        this.ecosystem = ecosystem;
        this.purl = purl;
    }
    
    /**
     * Create an OSV package with no purl and the default ecosystem of "OSV-Fuzz"
     * @param name Package name
     */
    public OsvPackage(String name) {
        this(name, "OSS-Fuzz", null);
    }

    @Override
    public int hashCode() {
        if (Objects.nonNull(purl)) {
            return purl.hashCode();
        } else {
            return this.name.hashCode();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof OsvPackage)) {
            return false;
        }
        OsvPackage compare = (OsvPackage)o;
        return Objects.equals(this.name, compare.getName()) && Objects.equals(this.purl, compare.getPurl());
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the ecosystem
     */
    public String getEcosystem() {
        return ecosystem;
    }

    /**
     * @return the purl
     */
    public @Nullable String getPurl() {
        return purl;
    }
}
