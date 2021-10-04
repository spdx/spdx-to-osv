/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

/**
 * @author Gary O'Neall
 *
 */
public class SpdxToOsvException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public SpdxToOsvException() {
    }

    /**
     * @param message
     */
    public SpdxToOsvException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public SpdxToOsvException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public SpdxToOsvException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public SpdxToOsvException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
