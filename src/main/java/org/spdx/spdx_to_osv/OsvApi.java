/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.spdx.spdx_to_osv.osvmodel.OsvErrorResponse;
import org.spdx.spdx_to_osv.osvmodel.OsvVulnerability;
import org.spdx.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;
import org.spdx.spdx_to_osv.osvmodel.OsvVulnerabilityResponse;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Singleton class for the OSV REST API
 * 
 * @author Gary O'Neall
 *
 */
public class OsvApi {
    
    private static OsvApi _instance;
    protected static String API_URL_STRING = "https://api.osv.dev/v1/query";
    protected URL apiUrl;
    static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    
    private OsvApi() {
        try {
            apiUrl  = new URL(API_URL_STRING);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized static OsvApi getInstance() {
        if (Objects.isNull(_instance)) {
            _instance = new OsvApi();
        }
        return _instance;
    }

    /**
     * Calls the QueryVulnerabilities API to obtain vulnerability information from OSV
     * @param packageNameVersion The package name and version object to pass to the OSV API
     * @return collection of OSV Vulnerabilities returned by the API
     * @throws IOException 
     * @throws SpdxToOsvException 
     */
    public List<OsvVulnerability> queryVulnerabilities(OsvVulnerabilityRequest packageNameVersion) throws IOException, SpdxToOsvException {
        HttpURLConnection con = (HttpURLConnection)(apiUrl.openConnection());
        String pkgNameVersionJson = GSON.toJson(packageNameVersion);
        byte[] json = pkgNameVersionJson.getBytes(StandardCharsets.UTF_8);
        int len = json.length;
        con.setRequestMethod("POST");
        con.setFixedLengthStreamingMode(len);
        con.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        con.setRequestProperty("Accept", "application/json");
        con.setDoOutput(true);
        con.connect();
        try {
	        try(OutputStream out = con.getOutputStream()) {
	        	if (Objects.nonNull(out)) {
	        		out.write(json);
	        	}
	        }
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
	            OsvVulnerabilityResponse responseJson = GSON.fromJson(response, OsvVulnerabilityResponse.class);
	            if (Objects.nonNull(responseJson.getVulns())) {
	                return responseJson.getVulns();
	            } else {
	                return new ArrayList<OsvVulnerability>();
	            }
	        } else {
	            OsvErrorResponse responseJson = GSON.fromJson(response, OsvErrorResponse.class);
	            String msg = "Error getting vulnerability data";
	            if (Objects.nonNull(responseJson) && Objects.nonNull(responseJson.getMessage()) &&
	                    !responseJson.getMessage().isEmpty()) {
	                msg += responseJson.getMessage();
	            }
	            throw new SpdxToOsvException(msg);
	        }
        } finally {
        	con.disconnect();
        }
    }
}
