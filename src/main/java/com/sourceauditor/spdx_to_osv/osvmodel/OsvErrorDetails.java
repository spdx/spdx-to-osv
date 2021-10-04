/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv.osvmodel;

/**
 * OSV object holding error details
 * 
 * @author Gary O'Neall
 *
 */
public class OsvErrorDetails {
    String typeUrl;
    String value;
    
    public OsvErrorDetails() {
        // required empty constructor
    }

    /**
     * @return the typeUrl
     */
    public String getTypeUrl() {
        return typeUrl;
    }

    /**
     * @param typeUrl the typeUrl to set
     */
    public void setTypeUrl(String typeUrl) {
        this.typeUrl = typeUrl;
    }

    /**
     * @return the value
     */
    public String getValue() {
        return value;
    }

    /**
     * @param value the value to set
     */
    public void setValue(String value) {
        this.value = value;
    }
    
    
}
