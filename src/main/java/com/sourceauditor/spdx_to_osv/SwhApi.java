/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Singleton class API for SoftwareHeritage
 * @author Gary O'Neall
 *
 */
public class SwhApi {
	
	private static SwhApi _instance;
	static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
	
	public static final String ENDPOINT = "https://archive.softwareheritage.org/api/1/";
	public static final String RELEASE_ENDPOINT = ENDPOINT + "release/";
	
	private SwhApi() {
		
	}
	
	public synchronized static SwhApi getInstance() {
		if (Objects.isNull(_instance)) {
			_instance = new SwhApi();
		}
		return _instance;
	}
	
	public SwhRelease getSwhRelease(String releaseSha1) throws IOException, SwhException {
		try {
			URL url = new URL(RELEASE_ENDPOINT + releaseSha1 + "/");
			return GSON.fromJson(getResponseString(url), SwhRelease.class);
		} catch (MalformedURLException e) {
			throw new RuntimeException("Malformed URL when getting Software Heritage Release",e);
		}
	}
	
	/**
	 * @param url URL to "get" the response
	 * @return String representing the response
	 */
	private String getResponseString(URL url) throws IOException, SwhException {
		HttpURLConnection con = (HttpURLConnection)(url.openConnection());
		con.setRequestMethod("GET");
		con.setRequestProperty("Accept", "application/json");
		con.connect();
		try {
			String response;
	        try(BufferedReader reader = new BufferedReader(
	                new InputStreamReader(con.getInputStream(),StandardCharsets.UTF_8))) {
	            StringBuilder sb = new StringBuilder();
	            String line = null;
	            while ((line = reader.readLine()) != null) {
	                sb.append(line);
	            }
	            response = sb.toString();
	        }
	        if (con.getResponseCode() == 200) {
	        	return response;
	        } else if (con.getResponseCode() == 404){
	        	throw new SwhResourceNotFoundException("Resource not found for URL "+url);
	        } else {
	        	throw new SwhApiException("Unexpected response code from SwhApi: "+con.getResponseCode());
	        }
		} finally {
			con.disconnect();
		}
	}

}
