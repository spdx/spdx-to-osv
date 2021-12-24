/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.storage.IModelStore;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.tools.InvalidFileNameException;
import org.spdx.tools.SpdxToolsHelper;
import org.spdx.tools.SpdxToolsHelper.SerFileType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvPackage;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerability;

/**
 * Utility to produce an OSV JSON file from an SPDX file
 * 
 * See https://osv.dev/ for information on OSV
 * 
 * The utility produces an output file OSVOutput.json in the OSV JSON format
 * See https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit for output format
 * 
 * @author Gary O'Neall
 */
public class Main {
    
    static final int ERROR_STATUS = 1;
    static final int SUCCESS_STATUS = 0;

    /**
     * @param args args[0] input SPDX file, args[1] output OSV JSON file
     */
    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Invalid number of arguments.");
            usage();
            System.exit(ERROR_STATUS);
        }
        File fromFile = new File(args[0]);
        File toFile = new File(args[1]);
        try {
            spdxToOsv(fromFile, toFile);
            System.exit(SUCCESS_STATUS);
        } catch(Exception ex) {
            System.err.println("Error converting SPDX file to OSV.");
            if (Objects.nonNull(ex.getMessage())) {
                System.err.println(ex.getMessage());
            }
            usage();
            System.exit(ERROR_STATUS);
        }
    }
    
    /**
     * Produce an OSV Output File from an SPDX input file
     * @param fromFile SPDX input file
     * @param toFile OSV output file
     * @throws SpdxToOsvException 
     * @throws IOException 
     */
    public static void spdxToOsv(File fromFile, File toFile) throws SpdxToOsvException, IOException {
        if (!fromFile.exists()) {
            throw new SpdxToOsvException("Input file "+fromFile.getName()+" does not exist");
        }
        if (toFile.exists()) {
            throw new SpdxToOsvException("Output file "+toFile.getName()+" already exists.");
        }
        InputStream inStream = null;
        Writer writer = null;
        try {
            SerFileType inputFileType = null;
            try {
                inputFileType = SpdxToolsHelper.fileToFileType(fromFile);
            } catch (InvalidFileNameException e) {
                throw new SpdxToOsvException("Invalid file extension for input file "+fromFile.getName());
            }
            writer = new OutputStreamWriter(new FileOutputStream(toFile), StandardCharsets.UTF_8);
            inStream = new FileInputStream(fromFile);
            spdxToOsv(inStream, inputFileType, writer);
        } finally {
            if (Objects.nonNull(inStream)) {
                inStream.close();
            }
            if (Objects.nonNull(writer)) {
                writer.close();
            }
        }
    }
    
    /**
     * Writes OSV JSON data to the outStream based on an SPDX model store and document URI
     * @param fromStore Model store containing the SPDX model
     * @param documentUri Document URI for the document to use
     * @param writer writer the OSV file
     * @throws SpdxToOsvException
     * @throws IOException 
     * @throws InvalidSPDXAnalysisException 
     */
    public static void spdxToOsv(IModelStore fromStore, String documentUri, Writer writer) throws SpdxToOsvException, IOException, InvalidSPDXAnalysisException {
    	OsvApi osvApi = OsvApi.getInstance();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        Set<OsvVulnerabilityRequest> pvSet = new HashSet<>();
        SpdxModelFactory.getElements(fromStore, documentUri, null, SpdxPackage.class).forEach(oPackage -> {
            try {
                SpdxPackage pkg = (SpdxPackage)oPackage;
                Optional<String> packageName = pkg.getName();
                Optional<String> version = pkg.getVersionInfo();
                if (packageName.isPresent() && version.isPresent()) {
                    pvSet.add(new OsvVulnerabilityRequest(new OsvPackage(packageName.get(), "OSS-Fuzz", null),
                            version.get()));
                }
                for (ExternalRef externalRef:pkg.getExternalRefs()) {
                    try {
                        Optional<OsvVulnerabilityRequest> pnv = new ExternalRefParser(externalRef).osvVulnerabilityRequest();
                        if (pnv.isPresent()) {
                            pvSet.add(pnv.get());
                        }
                    } catch (InvalidExternalRefPattern e) {
                        System.err.println("Warning: Error parsing external ref: "+e.getMessage());
                    } catch (IOException e) {
                    	System.err.println("Warning: I/O Error parsing external ref: "+e.getMessage());
					} catch (SwhException e) {
						System.err.println("Warning: Software Heritage API error while processing external ref: "+e.getMessage());
					}
                }
                // Get additional versions and commits from download locations
                Optional<String> downloadLocation = pkg.getDownloadLocation();
                if (downloadLocation.isPresent()) {
                    Optional<OsvVulnerabilityRequest> pnv = new DownloadLocationParser(downloadLocation.get()).getOsvVulnerabilityRequest();
                    if (pnv.isPresent()) {
                        pvSet.add(pnv.get());
                    }
                }
            } catch (InvalidSPDXAnalysisException ex) {
                throw new RuntimeException(ex);
            }
        });
        // call the API on all the package name versions
        writer.append('[');
        int numVulns = 0;
        for (OsvVulnerabilityRequest pnv:pvSet) {
            for (OsvVulnerability vulnerability:osvApi.queryVulnerabilities(pnv)) {
                if (numVulns > 0) {
	                writer.append(',');
	                writer.append('\n');
                }
                gson.toJson(vulnerability, writer);
                numVulns++;
            }
        }
        writer.append(']');
    }

    /**
     * Writes OSV JSON data to the outStream based on an SPDX input stream
     * @param inStream Stream for the SPDX file
     * @param inputFileType Serialization type for the input file stream
     * @param writer writer the OSV file
     * @throws SpdxToOsvException 
     */
    public static void spdxToOsv(InputStream inStream, SerFileType inputFileType, Writer writer) throws SpdxToOsvException {
        try {
            ISerializableModelStore fromStore = SpdxToolsHelper.fileTypeToStore(inputFileType);
            String documentUri = fromStore.deSerialize(inStream, false);
            spdxToOsv(fromStore, documentUri, writer);
        } catch (InvalidSPDXAnalysisException e) {
            throw new SpdxToOsvException("Error reading the SPDX input file",e);
        } catch (IOException e) {
            throw new SpdxToOsvException("I/O error converting SPDX to OSV",e);
        }
    }

    private static void usage() {
        System.out.println("-jar spdx-to-osv-with-dependencies.jar SpdxFile.spdx OSVOutput.json");
        System.out.println();
        System.out.println("where SpdxFile.spdx is an SPDX file in one of the following file extensions:");
        System.out.println("- .json JSON SPDX format");
        System.out.println("- .yaml YAML SPDX format");
        System.out.println("- .spdx Tag/Value SPDX format");
        System.out.println("- .rdf.xml, .rdf - RDF/XML SPDX format");
        System.out.println("- .xlsx, .xls Spreadsheet SPDX format");
    }

}
