/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv.osvmodel;

/**
 * Object for a response from the OSV-QueryAffected API based on https://osv.dev/docs/#operation/OSV_QueryAffected
 * 
 * @author Gary O'Neall
 *
 */
public class OsvErrorResponse {
    String code;
    String message;
    OsvErrorDetails details;
    
    public OsvErrorResponse() {
        // required empty constructor
    }

    /**
     * @return the code
     */
    public String getCode() {
        return code;
    }

    /**
     * @param code the code to set
     */
    public void setCode(String code) {
        this.code = code;
    }

    /**
     * @return the message
     */
    public String getMessage() {
        return message;
    }

    /**
     * @param message the message to set
     */
    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * @return the details
     */
    public OsvErrorDetails getDetails() {
        return details;
    }

    /**
     * @param details the details to set
     */
    public void setDetails(OsvErrorDetails details) {
        this.details = details;
    }
    
}
