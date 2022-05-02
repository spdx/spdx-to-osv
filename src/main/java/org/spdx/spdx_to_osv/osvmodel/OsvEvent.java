/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv.osvmodel;

/**
 * OSV event object as described at https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit
 * 
 * @author Gary O'Neall
 */
public class OsvEvent {
    
    /**
     * The earliest version/commit where this vulnerability was introduced in.
     */
    String introduced;
    
    /**
     * The version/commit that this vulnerability was fixed in.
     */
    String fixed;
    
    /**
     * The limit to apply to the range.
     */
    String limit;
    
    /**
     * Required empty constructor
     */
    public OsvEvent() {
        
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

    /**
     * @return the limit
     */
    public String getLimit() {
        return limit;
    }

    /**
     * @param limit the limit to set
     */
    public void setLimit(String limit) {
        this.limit = limit;
    }

}
