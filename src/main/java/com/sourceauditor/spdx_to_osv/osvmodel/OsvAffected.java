/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv.osvmodel;

import java.util.List;

import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * OSV Affected object as described at https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit
 * 
 * @author Gary O'Neall
 */
public class OsvAffected {
    
    /**
     * Package information and version.
     */
    @SerializedName(value="package")
    OsvPackage osvPackage;
    
    /**
     * Required. Range information.
     */
    List<OsvRange> ranges;
    
    /**
     * Optional. List of affected versions.
     */
    List<String> versions;
    
    /**
     * Optional. JSON object holding additional information about the vulnerability 
     * as defined by the ecosystem for which the record applies.
     */
    JsonObject ecosystemSpecific;
    
    /**
     * Optional. JSON object holding additional information about the vulnerability 
     * as defined by the database for which the record applies.
     */
    JsonObject databaseSpecific;

    /**
     * Required empty constructor
     */
    public OsvAffected() {
        
    }

    /**
     * @return the osvPackage
     */
    public OsvPackage getOsvPackage() {
        return osvPackage;
    }

    /**
     * @param osvPackage the osvPackage to set
     */
    public void setOsvPackage(OsvPackage osvPackage) {
        this.osvPackage = osvPackage;
    }

    /**
     * @return the ranges
     */
    public List<OsvRange> getRanges() {
        return ranges;
    }

    /**
     * @param ranges the ranges to set
     */
    public void setRanges(List<OsvRange> ranges) {
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

    /**
     * @return the ecosystemSpecific
     */
    public JsonObject getEcosystemSpecific() {
        return ecosystemSpecific;
    }

    /**
     * @param ecosystemSpecific the ecosystemSpecific to set
     */
    public void setEcosystemSpecific(JsonObject ecosystemSpecific) {
        this.ecosystemSpecific = ecosystemSpecific;
    }

    /**
     * @return the databaseSpecific
     */
    public JsonObject getDatabaseSpecific() {
        return databaseSpecific;
    }

    /**
     * @param databaseSpecific the databaseSpecific to set
     */
    public void setDatabaseSpecific(JsonObject databaseSpecific) {
        this.databaseSpecific = databaseSpecific;
    }
    
}
