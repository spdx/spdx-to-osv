/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.model.ExternalRef;

import com.sourceauditor.spdx_to_osv.osvmodel.OsvPackage;
import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * Parses an ExternalRef
 * 
 * @author Gary O'Neall
 *
 */
public class ExternalRefParser {
    
    public static final Pattern CPE22_PATTERN = Pattern.compile("[c][pP][eE]:(/[AHOaho]?)(:[A-Za-z0-9\\\\._\\\\-~%]*){0,6}");
    public static final Pattern CPE23_PATTERN = Pattern.compile("cpe:2\\\\.3:([aho\\\\*\\\\­])(:(((\\\\?*|\\\\*?)([a­zA­Z0­9\\\\­\\\\._]|(\\\\\\\\[\\\\\\\\\\\\*\\\\?!\\#$$%&'\\\\(\\\\)\\\\+,/:;<=>@\\\\[\\\\]\\\\^`\\\\{\\\\|}~]))+(\\\\?*|\\\\*?))|[\\\\*\\\\­])){5}(:(([a­zA­Z]{2,3}(­([a­zA­Z]{2}|[0­9]{3}))?)|[\\\\*\\\\­]))(:(((\\\\?*|\\\\*?)([a­zA­Z0­9\\\\­\\\\._]|(\\\\\\\\[\\\\\\\\\\\\*\\\\?!\\#$$%&'\\\\(\\\\)\\\\+,/:;<=>@\\\\[\\\\]\\\\^`\\\\{\\\\|}~]))+(\\\\?*|\\\\*?))|[\\\\*\\\\­])){4}");
    
    public enum CPE_PART {
        NONE,
        HARDWARE,   // h
        OPERATING_SYSTEM,   // o
        APPLICATION     // a
    }
    
    private ExternalRef externalRef;
    Optional<OsvVulnerabilityRequest> packageNameVersion = Optional.empty();
    Optional<CPE_PART> cpePart = Optional.empty();
    Optional<String> vendor = Optional.empty(); // CPE vendor
    Optional<String> update = Optional.empty(); // CPE update
    Optional<String> edition = Optional.empty(); // CPE edition
    Optional<String> language = Optional.empty(); // CPE language
    private Optional<String> swEdition = Optional.empty(); // CPE sw_edition
    private Optional<String> targetSw = Optional.empty(); // CPE target_sw
    private Optional<String> targetHw = Optional.empty(); // CPE target_hw
    private Optional<String> cpeOther = Optional.empty(); // CPE other
    

    public ExternalRefParser(ExternalRef externalRef) throws InvalidSPDXAnalysisException, InvalidExternalRefPattern {
        this.externalRef = externalRef;
        // Parse the PackageNameVersion
        if (externalRef.getReferenceType().getIndividualURI().endsWith("/cpe22Type")) {
            parseCpe22(externalRef.getReferenceLocator());
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("/cpe23Type")) {
            parseCpe32(externalRef.getReferenceLocator());
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("/maven-central")) {
            parseMavenCentral(externalRef.getReferenceLocator());
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("/npm")) {
            parseNpm(externalRef.getReferenceLocator());
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("/nuget")) {
            parseNuget(externalRef.getReferenceLocator());
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("/bower")) {
            parseBower(externalRef.getReferenceLocator());
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("/purl")) {
            paserPurl(externalRef.getReferenceLocator());
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("/swh")) {
            parseSwh(externalRef.getReferenceLocator());
        } else {
            packageNameVersion = Optional.empty();
        }
    }

    /**
     * @param referenceLocator
     */
    private void parseSwh(String referenceLocator) {
        // TODO Auto-generated method stub
        throw new RuntimeException("Not yet implemented");
    }

    /**
     * @param referenceLocator
     */
    private void paserPurl(String referenceLocator) {
        // TODO Auto-generated method stub
        throw new RuntimeException("Not yet implemented");
        
    }

    /**
     * @param referenceLocator
     */
    private void parseBower(String referenceLocator) {
        // TODO Auto-generated method stub
        throw new RuntimeException("Not yet implemented");
    }

    /**
     * @param referenceLocator
     */
    private void parseNuget(String referenceLocator) {
        // TODO Auto-generated method stub
        throw new RuntimeException("Not yet implemented");
    }

    /**
     * @param referenceLocator
     */
    private void parseNpm(String referenceLocator) {
        // TODO Auto-generated method stub
        throw new RuntimeException("Not yet implemented");
    }

    /**
     * @param referenceLocator
     * @throws InvalidExternalRefPattern 
     */
    private void parseMavenCentral(String referenceLocator) throws InvalidExternalRefPattern {
        String[] parts = referenceLocator.split(":");
        if (parts.length < 3) {
            throw new InvalidExternalRefPattern("Maven central string must have at least the group and artifact");
        }
        cpePart = Optional.of(CPE_PART.APPLICATION);
        this.packageNameVersion = Optional.of(new PackageNameVersion());
    }

    /**
     * @param referenceLocator
     * @throws InvalidSPDXAnalysisException 
     * @throws InvalidExternalRefPattern 
     */
    private void parseCpe32(String referenceLocator) throws InvalidExternalRefPattern, InvalidSPDXAnalysisException {
        Matcher matcher = CPE23_PATTERN.matcher(referenceLocator);
        if (matcher.matches()) {
            String partStr = matcher.group(1).toLowerCase().trim();
            if (partStr.equals("-") || partStr.equals("*")) {
                cpePart = Optional.of(CPE_PART.NONE);
            } else if (partStr.equals("h")) {
                cpePart = Optional.of(CPE_PART.HARDWARE);
            } else if (partStr.equals("o")) {
                cpePart = Optional.of(CPE_PART.OPERATING_SYSTEM);
            } else if (partStr.equals("a")) {
                cpePart = Optional.of(CPE_PART.APPLICATION);
            } else {
                throw new InvalidExternalRefPattern("CPE23 external ref locater "+externalRef.getReferenceLocator() +
                        " contains an invalid part string " + matcher.group(1));
            }
            if (matcher.groupCount() > 1 && !matcher.group(2).trim().isEmpty() &&
                    !"-".equals(matcher.group(2).trim()) && !"*".equals(matcher.group(2).trim())) {
                // vendor
                vendor = Optional.of(matcher.group(2));
            }
            if (matcher.groupCount() > 2 && !matcher.group(3).trim().isEmpty() &&
                    !"-".equals(matcher.group(3).trim()) && !"*".equals(matcher.group(3).trim())) {
                // product
                if (matcher.groupCount() > 3 && !matcher.group(4).trim().isEmpty() &&
                        !"-".equals(matcher.group(4).trim()) && !"*".equals(matcher.group(4).trim())) {
                    // version
                    packageNameVersion = Optional.of(new OsvVulnerabilityRequest(new OsvPackage(matcher.group(3)), matcher.group(4)));
                } else {
                    packageNameVersion = Optional.of(new OsvVulnerabilityRequest(new OsvPackage(matcher.group(3)), null));
                }
            }
            
            if (matcher.groupCount() > 4 && !matcher.group(5).trim().isEmpty()  &&
                    !"-".equals(matcher.group(5).trim()) && !"*".equals(matcher.group(5).trim())) {
                // update
                this.update = Optional.of(matcher.group(5));
            }
            if (matcher.groupCount() > 5 && !matcher.group(6).trim().isEmpty() &&
                    !"-".equals(matcher.group(6).trim()) && !"*".equals(matcher.group(6).trim())) {
                // edition
                this.edition =  Optional.of(matcher.group(6));
            }
            if (matcher.groupCount() > 6 && !matcher.group(7).trim().isEmpty() &&
                    !"-".equals(matcher.group(7).trim()) && !"*".equals(matcher.group(7).trim())) {
                // language
                this.language = Optional.of(matcher.group(7));
            }
            if (matcher.groupCount() > 7 && !matcher.group(8).trim().isEmpty() &&
                    !"-".equals(matcher.group(8).trim()) && !"*".equals(matcher.group(8).trim())) {
                // language
                this.swEdition = Optional.of(matcher.group(8));
            }
            if (matcher.groupCount() > 8 && !matcher.group(9).trim().isEmpty() &&
                    !"-".equals(matcher.group(9).trim()) && !"*".equals(matcher.group(9).trim())) {
                // language
                this.targetSw = Optional.of(matcher.group(9));
            }
            if (matcher.groupCount() > 9 && !matcher.group(10).trim().isEmpty() &&
                    !"-".equals(matcher.group(10).trim()) && !"*".equals(matcher.group(10).trim())) {
                // language
                this.targetHw = Optional.of(matcher.group(10));
            }
            if (matcher.groupCount() > 10 && !matcher.group(11).trim().isEmpty() &&
                    !"-".equals(matcher.group(11).trim()) && !"*".equals(matcher.group(11).trim())) {
                // language
                this.cpeOther = Optional.of(matcher.group(10));
            }
        } else {
            throw new InvalidExternalRefPattern("CPE23 external ref locater "+externalRef.getReferenceLocator() +
                    " does not match the pattern " + CPE23_PATTERN.toString());
        }
    }

    /**
     * Parses the CPE22 format per https://cpe.mitre.org/files/cpe-specification_2.2.pdf
     * @param referenceLocator
     * @throws InvalidSPDXAnalysisException 
     * @throws InvalidExternalRefPattern 
     */
    private void parseCpe22(String referenceLocator) throws InvalidExternalRefPattern, InvalidSPDXAnalysisException {
        Matcher matcher = CPE22_PATTERN.matcher(referenceLocator);
        if (matcher.matches()) {
            String partStr = matcher.group(1).toLowerCase().trim();
            if (partStr.isEmpty()) {
                cpePart = Optional.of(CPE_PART.NONE);
            } else if (partStr.equals("/h")) {
                cpePart = Optional.of(CPE_PART.HARDWARE);
            } else if (partStr.equals("/o")) {
                cpePart = Optional.of(CPE_PART.OPERATING_SYSTEM);
            } else if (partStr.equals("/a")) {
                cpePart = Optional.of(CPE_PART.APPLICATION);
            } else {
                throw new InvalidExternalRefPattern("CPE22 external ref locater "+externalRef.getReferenceLocator() +
                        " contains an invalid part string " + matcher.group(1));
            }
            if (matcher.groupCount() > 1 && !matcher.group(2).trim().isEmpty()) {
                // vendor
                vendor = Optional.of(matcher.group(2));
            }
            if (matcher.groupCount() > 2 && !matcher.group(3).trim().isEmpty()) {
                // product
                if (matcher.groupCount() > 3 && !matcher.group(4).trim().isEmpty()) {
                    // version
                    packageNameVersion = Optional.of(new OsvVulnerabilityRequest(new OsvPackage(matcher.group(3)), matcher.group(4)));
                } else {
                    packageNameVersion = Optional.of(new OsvVulnerabilityRequest(new OsvPackage(matcher.group(3)), null));
                }
            }
            
            if (matcher.groupCount() > 4 && !matcher.group(5).trim().isEmpty()) {
                // update
                this.update = Optional.of(matcher.group(5));
            }
            if (matcher.groupCount() > 5 && !matcher.group(6).trim().isEmpty()) {
                // edition
                this.edition =  Optional.of(matcher.group(6));
            }
            if (matcher.groupCount() > 6 && !matcher.group(7).trim().isEmpty()) {
                // language
                this.language = Optional.of(matcher.group(7));
            }
        } else {
            throw new InvalidExternalRefPattern("CPE22 external ref locater "+externalRef.getReferenceLocator() +
                    " does not match the pattern " + CPE22_PATTERN.toString());
        }
    }

    /**
     * @return the externalRef
     */
    public ExternalRef getExternalRef() {
        return externalRef;
    }

    /**
     * @return the packageNameVersion
     */
    public Optional<OsvVulnerabilityRequest> getPackageNameVersion() {
        return packageNameVersion;
    }

    /**
     * @return the cpePart
     */
    public Optional<CPE_PART> getCpePart() {
        return cpePart;
    }

    /**
     * @return the vendor
     */
    public Optional<String> getVendor() {
        return vendor;
    }

    /**
     * @return the update
     */
    public Optional<String> getUpdate() {
        return update;
    }

    /**
     * @return the edition
     */
    public Optional<String> getEdition() {
        return edition;
    }

    /**
     * @return the language
     */
    public Optional<String> getLanguage() {
        return language;
    }

    /**
     * @return the swEdition
     */
    public Optional<String> getSwEdition() {
        return swEdition;
    }

    /**
     * @return the targetSw
     */
    public Optional<String> getTargetSw() {
        return targetSw;
    }

    /**
     * @return the targetHw
     */
    public Optional<String> getTargetHw() {
        return targetHw;
    }

    /**
     * @return the cpeOther
     */
    public Optional<String> getCpeOther() {
        return cpeOther;
    }
    
}
