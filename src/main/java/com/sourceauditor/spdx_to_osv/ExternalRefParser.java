/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package com.sourceauditor.spdx_to_osv;

import java.util.Optional;

import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.model.ExternalRef;

import com.sourceauditor.spdx_to_osv.osvmodel.OsvVulnerabilityRequest;

/**
 * Parses an ExternalRef
 * 
 * @author Gary O'Neall
 *
 */
public class ExternalRefParser {
    
    private ExternalRef externalRef;
    Optional<OsvVulnerabilityRequest> packageNameVersion;

    public ExternalRefParser(ExternalRef externalRef) throws InvalidSPDXAnalysisException {
        this.externalRef = externalRef;
        // Parse the PackageNameVersion
        if (externalRef.getReferenceType().getIndividualURI().endsWith("cpe22Type")) {
            
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("cpe23Type")) {
            
        } else if (externalRef.getReferenceType().getIndividualURI().endsWith("maven-central")) {
            
        }
        //TODO: fill in the reset
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
}
