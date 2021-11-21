/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

/**
 * Exception calling the Software Heritage API's
 * 
 * @author Gary O'Neall
 *
 */
public class SwhApiException extends SwhException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * 
	 */
	public SwhApiException() {
	}

	/**
	 * @param arg0
	 */
	public SwhApiException(String arg0) {
		super(arg0);
	}

	/**
	 * @param arg0
	 */
	public SwhApiException(Throwable arg0) {
		super(arg0);
	}

	/**
	 * @param arg0
	 * @param arg1
	 */
	public SwhApiException(String arg0, Throwable arg1) {
		super(arg0, arg1);
	}

	/**
	 * @param arg0
	 * @param arg1
	 * @param arg2
	 * @param arg3
	 */
	public SwhApiException(String arg0, Throwable arg1, boolean arg2,
			boolean arg3) {
		super(arg0, arg1, arg2, arg3);
	}

}
