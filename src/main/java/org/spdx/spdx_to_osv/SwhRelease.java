/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv;

import com.google.gson.JsonObject;

/**
 * Result of a call to the Software Heritage API
 * 
 * @author Gary O'Neall
 *
 */
public class SwhRelease {
	
	private JsonObject author;
	private String date;
	private String id;
	private String message;
	private String name;
	private String target;
	private String target_type;
	private String target_url;
	/**
	 * @return the author
	 */
	public JsonObject getAuthor() {
		return author;
	}
	/**
	 * @param author the author to set
	 */
	public void setAuthor(JsonObject author) {
		this.author = author;
	}
	/**
	 * @return the date
	 */
	public String getDate() {
		return date;
	}
	/**
	 * @param date the date to set
	 */
	public void setDate(String date) {
		this.date = date;
	}
	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}
	/**
	 * @param id the id to set
	 */
	public void setId(String id) {
		this.id = id;
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
	 * @return the name
	 */
	public String getName() {
		return name;
	}
	/**
	 * @param name the name to set
	 */
	public void setName(String name) {
		this.name = name;
	}
	/**
	 * @return the target
	 */
	public String getTarget() {
		return target;
	}
	/**
	 * @param target the target to set
	 */
	public void setTarget(String target) {
		this.target = target;
	}
	/**
	 * @return the target_type
	 */
	public String getTarget_type() {
		return target_type;
	}
	/**
	 * @param target_type the target_type to set
	 */
	public void setTarget_type(String target_type) {
		this.target_type = target_type;
	}
	/**
	 * @return the target_url
	 */
	public String getTarget_url() {
		return target_url;
	}
	/**
	 * @param target_url the target_url to set
	 */
	public void setTarget_url(String target_url) {
		this.target_url = target_url;
	}
	
	

}
