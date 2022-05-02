/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.SpdxConstants;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.Relationship;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxElement;
import org.spdx.library.model.SpdxFile;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.enumerations.RelationshipType;
import org.spdx.spdx_to_osv.osvmodel.OsvPackage;
import org.spdx.spdx_to_osv.osvmodel.OsvVulnerability;
import org.spdx.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;
import org.spdx.storage.IModelStore;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.tools.SpdxToolsHelper;
import org.spdx.tools.SpdxToolsHelper.SerFileType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

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
     * Forward relationships that may cause a security vulnerability 
     * (e.g. A depends_on B.  B has a vulnerability.  A may have a vulnerability)
     */
    static final Set<RelationshipType> RELEVANT_RELATIONSHIPS = new HashSet<>();
    /**
     * Reverse relationships that may cause a security vulnerability 
     * (e.g. A is_a_dependency_of B.  A has a vulnerability.  B may have a vulnerability)
     */
    static final Set<RelationshipType> RELEVANT_REVERSE_RELATIONSHIPS = new HashSet<>();
    /**
     * Relationships which do not impact the security of either side of the relationship
     */
    static final Set<RelationshipType> NON_RELEVANT_RELATIONSHIPS = new HashSet<>();
    
    static {
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.CONTAINS);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.COPY_OF);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.DYNAMIC_LINK);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.EXPANDED_FROM_ARCHIVE);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.FILE_ADDED);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.GENERATED_FROM);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.GENERATED_FROM);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.PACKAGE_OF);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.PATCH_FOR);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.STATIC_LINK);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.HAS_PREREQUISITE);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.VARIANT_OF);
    	RELEVANT_RELATIONSHIPS.add(RelationshipType.DEPENDS_ON);
    	
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.CONTAINED_BY);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.COPY_OF);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.DISTRIBUTION_ARTIFACT);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.GENERATES);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.OPTIONAL_COMPONENT_OF);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.PACKAGE_OF);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.PATCH_APPLIED);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.PREREQUISITE_FOR);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.VARIANT_OF);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.DEPENDENCY_OF);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.OPTIONAL_DEPENDENCY_OF);
    	RELEVANT_REVERSE_RELATIONSHIPS.add(RelationshipType.RUNTIME_DEPENDENCY_OF);
    	
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DESCRIBES);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DESCRIBED_BY);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.ANCESTOR_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.BUILD_TOOL_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DATA_FILE_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DESCENDANT_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DOCUMENTATION_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.FILE_DELETED);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.FILE_MODIFIED);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.METAFILE_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.OTHER);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.AMENDS);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.TEST_CASE_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.MISSING);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.BUILD_DEPENDENCY_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DEPENDENCY_MANIFEST_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DEV_DEPENDENCY_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.DEV_TOOL_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.EXAMPLE_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.PROVIDED_DEPENDENCY_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.TEST_DEPENDENCY_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.TEST_OF);
    	NON_RELEVANT_RELATIONSHIPS.add(RelationshipType.TEST_TOOL_OF);
    }
    

    /**
     * @param args args[0] input SPDX file, args[1] output OSV JSON file
     */
    public static void main(String[] args) {
		Options options = createOptions();
		if (args.length == 1 && "-h".equals(args[0])) {
			usage(options);
			System.exit(0);
		}
		CommandLineParser parser = new DefaultParser();
		CommandLine cmdLine = null;
		try {
			cmdLine = parser.parse(options, args);
		} catch (ParseException e1) {
			System.out.println(e1.getMessage());
			usage(options);
			System.exit(ERROR_STATUS);
		}
        File fromFile = new File(cmdLine.getOptionValue("I").trim());
        File toFile = new File(cmdLine.getOptionValue("O").trim());
        SerFileType inputFileType = null;
        if (cmdLine.hasOption("f")) {
        	try {
                inputFileType = SpdxToolsHelper.strToFileType(cmdLine.getOptionValue("f").trim());
            } catch (Exception e) {
                System.out.println("Invalid file type "+cmdLine.getOptionValue("f").trim() + 
                		".  Expecting RDFXML, JSON, XLS, XLSX, YAML, or TAG");
                System.exit(ERROR_STATUS);
            }
        }
        try {
            inputFileType = SpdxToolsHelper.fileToFileType(fromFile);
        } catch (Exception e) {
            System.out.println("Invalid file extension for input file "+fromFile.getName());
            System.exit(ERROR_STATUS);
        }
        boolean allPackages = cmdLine.hasOption("a");
        try {
            spdxToOsv(fromFile, toFile, inputFileType, allPackages);
            System.exit(SUCCESS_STATUS);
        } catch(Exception ex) {
            System.err.println("Error converting SPDX file to OSV.");
            if (Objects.nonNull(ex.getMessage())) {
                System.err.println(ex.getMessage());
            }
            usage(options);
            System.exit(ERROR_STATUS);
        }
    }
    
    /**
	 * @return Options for the spdx-to-osv comand
	 */
	private static Options createOptions() {
		Options retval = new Options();
		retval.addOption(Option.builder("I")
				.longOpt("input")
				.desc("Input SPDX file in one of the supported formats (json, yaml, tag/value, xls, xlsx, rdf/xml)")
				.hasArg(true)
				.required(true)
				.build()
				);
		retval.addOption(Option.builder("O")
				.longOpt("output")
				.desc("output file name.  File will be in the OSV JSON format")
				.hasArg(true)
				.required(true)
				.build()
				);
		retval.addOption(Option.builder("f")
				.longOpt("inputFormat")
				.desc("Input file format - RDFXML, JSON, XLS, XLSX, YAML, or TAG")
				.hasArg(true)
				.required(false)
				.build()
				);
		retval.addOption(Option.builder("a")
				.longOpt("all")
				.desc("Include vulnerabilities for all packages in the SPDX file. "
						+ "Default is to only include vulnerabilities related to the element described by the document.")
				.hasArg(false)
				.required(false)
				.build()
				);
		return retval;
	}

	/**
     * Produce an OSV Output File from an SPDX input file
     * @param fromFile SPDX input file
     * @param toFile OSV output file
     * @param inputFileType Input file type for the SPDX file
     * @param allPackage if true, scan all packages in the document
     * @throws SpdxToOsvException 
     * @throws IOException 
     */
    public static void spdxToOsv(File fromFile, File toFile, SerFileType inputFileType, boolean allPackages) throws SpdxToOsvException, IOException {
        if (!fromFile.exists()) {
            throw new SpdxToOsvException("Input file "+fromFile.getName()+" does not exist");
        }
        if (toFile.exists()) {
            throw new SpdxToOsvException("Output file "+toFile.getName()+" already exists.");
        }
        InputStream inStream = null;
        Writer writer = null;
        try {
            writer = new OutputStreamWriter(new FileOutputStream(toFile), StandardCharsets.UTF_8);
            inStream = new FileInputStream(fromFile);
            spdxToOsv(inStream, inputFileType, writer, allPackages);
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
     * @param allPackage if true, scan all packages in the document
     * @throws SpdxToOsvException
     * @throws IOException 
     * @throws InvalidSPDXAnalysisException 
     */
    public static void spdxToOsv(IModelStore fromStore, String documentUri, Writer writer, boolean allPackages) throws SpdxToOsvException, IOException, InvalidSPDXAnalysisException {
    	OsvApi osvApi = OsvApi.getInstance();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        Set<OsvVulnerabilityRequest> pvSet = new HashSet<>();
        List<SpdxPackage> pkgs = getPackageFromDocument(fromStore, documentUri, allPackages);
        for (SpdxPackage pkg:pkgs) {
            try {
                Optional<String> packageName = pkg.getName();
                Optional<String> version = pkg.getVersionInfo();
                if (packageName.isPresent() && version.isPresent()) {
                    String pName = packageName.get();

                    // Some SPDX documents are created with the package name
                    // including the versions. Although these should be parsed
                    // by the creator, this code will workaround the package names.
                    pName = pName.split("@")[0];
                    pvSet.add(new OsvVulnerabilityRequest(new OsvPackage(pName, null, null),
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
                        OsvVulnerabilityRequest req = pnv.get();
                        if (req.getVersion() == null && req.getCommit() == null) {
                            if (version.isPresent()) {
                                req.setVersion(version.get());
                            } else {
                                System.err.printf("Warning: Unable to query package %s due to missing version/commit info", req.getPackage().getName());
                                continue;
                            }
                        }
                        pvSet.add(req);
                    }
                }
            } catch (InvalidSPDXAnalysisException ex) {
                throw new RuntimeException(ex);
            }
        }
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
     * @param fromStore Model store containing the SPDX model
     * @param documentUri Document URI for the document to use
	 * @param allPackages if true, scan all packages in the document
	 * @return list of packages to be examined based on the allPackages paramater and dependencies of any documentDescribes element
     * @throws InvalidSPDXAnalysisException 
	 */
	private static List<SpdxPackage> getPackageFromDocument(
			IModelStore fromStore, String documentUri, boolean allPackages) throws InvalidSPDXAnalysisException {
		if (allPackages) {
			List<SpdxPackage> retval = new ArrayList<>();
			SpdxModelFactory.getElements(fromStore, documentUri, null, SpdxPackage.class).forEach(oPackage -> {
	                retval.add((SpdxPackage)oPackage);
			});
			return retval;
		} else {
			SpdxDocument doc = (SpdxDocument)(SpdxModelFactory.getModelObject(fromStore, documentUri, SpdxConstants.SPDX_DOCUMENT_ID, 
					SpdxConstants.CLASS_SPDX_DOCUMENT, null, false));
			if (Objects.isNull(doc)) {
				throw new InvalidSPDXAnalysisException("Missing document ID");
			}
			Map<String, List<Relationship>> fromElementIdRelationshipMap = new HashMap<>();
			Map<String, List<SpdxElement>> toElementIdToRelationship = new HashMap<>();
			// Collect all the relationships from Files and Packages that have a relevant relationship type
			SpdxModelFactory.getElements(fromStore, documentUri, null, SpdxPackage.class).forEach(oPackage -> {
				try {
					addRelevantRelationships((SpdxElement)oPackage, fromElementIdRelationshipMap, 
							toElementIdToRelationship);
				} catch (InvalidSPDXAnalysisException e) {
					throw new RuntimeException("Error parsing relationship graph",e);
				}
			});
			SpdxModelFactory.getElements(fromStore, documentUri, null, SpdxFile.class).forEach(oFile -> {
				try {
					addRelevantRelationships((SpdxElement)oFile, fromElementIdRelationshipMap, 
							toElementIdToRelationship);
				} catch (InvalidSPDXAnalysisException e) {
					throw new RuntimeException("Error parsing relationship graph",e);
				}
			});
			List<SpdxPackage> retval = new ArrayList<>();
			Set<String> visitedElementIds = new HashSet<>();
			for (SpdxElement described:doc.getDocumentDescribes()) {
				if (!visitedElementIds.contains(described.getId())) {
					collectRelevantPackages(described, retval, 
							fromElementIdRelationshipMap, toElementIdToRelationship,
							visitedElementIds);
				}
			}
			return retval;
		}
	}

	/**
	 * Collects all of relevant packages related to element
	 * @param element element to search for relevant relationship
	 * @param relevantPackages result of packages which are added to
	 * @param toElementIdToRelationship map of element ID's to relevant relationships
	 * @param fromElementIdRelationshipMap map of from element ID's to the element containing the relevant relationship
	 * @param visitedElementIds Set of all element ID's visited by the collector - used to avoid infinite recursion
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void collectRelevantPackages(SpdxElement element, 
			List<SpdxPackage> relevantPackages, 
			Map<String, List<Relationship>> fromElementIdRelationshipMap, 
			Map<String, List<SpdxElement>> toElementIdToRelationship, 
			Set<String> visitedElementIds) throws InvalidSPDXAnalysisException {
		String id = element.getId();
		if (visitedElementIds.contains(id)) {
			return;
		}
		visitedElementIds.add(id);
		if (element instanceof SpdxPackage) {
			// if we're here, we're relevant!
			relevantPackages.add((SpdxPackage)element);
		}
		if (fromElementIdRelationshipMap.containsKey(id)) {
			for (Relationship relationship:fromElementIdRelationshipMap.get(id)) {
				if (relationship.getRelatedSpdxElement().isPresent()) {
					collectRelevantPackages(relationship.getRelatedSpdxElement().get(),
							relevantPackages, fromElementIdRelationshipMap,
							toElementIdToRelationship, visitedElementIds);
				}
			}
		}
		if (toElementIdToRelationship.containsKey(id)) {
			for (SpdxElement relatedElement:toElementIdToRelationship.get(id)) {
				collectRelevantPackages(relatedElement, relevantPackages, 
						fromElementIdRelationshipMap,
						toElementIdToRelationship, visitedElementIds);
			}
		}
	}

	/**
	 * Add relationships from the element to the relationship maps collecting any relationship
	 * considered relevant to possible security violations (e.g. development and test relationships would
	 * be excluded)
	 * @param element Element containing the relationships
	 * @param fromElementIdRelationshipMap Map from an element ID to all of it's relevant relationships 
	 * @param toElementIdRelationshipMap
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void addRelevantRelationships(SpdxElement element,
			Map<String, List<Relationship>> fromElementIdRelationshipMap,
			Map<String, List<SpdxElement>> toElementIdRelationshipMap) throws InvalidSPDXAnalysisException {
		List<Relationship> elementRelationships = new ArrayList<>();
		fromElementIdRelationshipMap.put(element.getId(), elementRelationships);
		for (Relationship relationship:element.getRelationships()) {
			if (RELEVANT_RELATIONSHIPS.contains(relationship.getRelationshipType())) {
				elementRelationships.add(relationship);
			}
			if (RELEVANT_REVERSE_RELATIONSHIPS.contains(relationship.getRelationshipType()) &&
					relationship.getRelatedSpdxElement().isPresent()) {
				List<SpdxElement> reverseRelationships = toElementIdRelationshipMap.get(relationship.getRelatedSpdxElement().get().getId());
				if (Objects.isNull(reverseRelationships)) {
					reverseRelationships = new ArrayList<>();
					toElementIdRelationshipMap.put(relationship.getRelatedSpdxElement().get().getId(), reverseRelationships);
				}
				reverseRelationships.add(element);
			}
		}
	}

	/**
     * Writes OSV JSON data to the outStream based on an SPDX input stream
     * @param inStream Stream for the SPDX file
     * @param inputFileType Serialization type for the input file stream
     * @param writer writer the OSV file
     * @param allPackage if true, scan all packages in the document
     * @throws SpdxToOsvException 
     */
    public static void spdxToOsv(InputStream inStream, SerFileType inputFileType, Writer writer, boolean allPackages) throws SpdxToOsvException {
        try {
            ISerializableModelStore fromStore = SpdxToolsHelper.fileTypeToStore(inputFileType);
            String documentUri = fromStore.deSerialize(inStream, false);
            spdxToOsv(fromStore, documentUri, writer, allPackages);
        } catch (InvalidSPDXAnalysisException e) {
            throw new SpdxToOsvException("Error reading the SPDX input file",e);
        } catch (IOException e) {
            throw new SpdxToOsvException("I/O error converting SPDX to OSV",e);
        }
    }

	/**
	 * Print usage
	 */
	private static void usage(Options options) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp("spdx-to-osv", options);
	}




}
