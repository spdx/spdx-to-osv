/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv.osvmodel;

/**
 * OSV Reference object as described at https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit
 * 
 * @author Gary O'Neall
 */
public class OsvReference {
    
    enum OsvReferenceType {
        NONE,
        WEB,
        ADVISORY,
        REPORT,
        FIX,
        PACKAGE
    }
    
    /**
     * Default: "NONE"
     * Enum: "NONE" "WEB" "ADVISORY" "REPORT" "FIX" "PACKAGE"
     */
    OsvReferenceType type;
    
    /**
     * Required. The URL.
     */
    String url;

    /**
     * Required empty constructor
     */
    public OsvReference() {
        
    }

    /**
     * @return the type
     */
    public OsvReferenceType getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(OsvReferenceType type) {
        this.type = type;
    }

    /**
     * @return the url
     */
    public String getUrl() {
        return url;
    }

    /**
     * @param url the url to set
     */
    public void setUrl(String url) {
        this.url = url;
    }
    
}
