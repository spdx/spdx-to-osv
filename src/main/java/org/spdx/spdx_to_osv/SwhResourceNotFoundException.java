/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv;

/**
 * Exception when a resource is not found on the Software Heritage service
 * 
 * @author Gary O'Neall
 *
 */
public class SwhResourceNotFoundException extends SwhException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * 
	 */
	public SwhResourceNotFoundException() {
	}

	/**
	 * @param message
	 */
	public SwhResourceNotFoundException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public SwhResourceNotFoundException(Throwable cause) {
		super(cause);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public SwhResourceNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public SwhResourceNotFoundException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
