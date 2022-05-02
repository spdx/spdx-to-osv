/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Source Auditor Inc.
 */
package org.spdx.spdx_to_osv.osvmodel;

import java.util.List;

/**
 * OSV range object as described at https://docs.google.com/document/d/1sylBGNooKtf220RHQn1I8pZRmqXZQADDQ_TOABrKTpA/edit
 * 
 * @author Gary O'Neall
 */
public class OsvRange {
    
    public enum OsvRangeType {
        UNSPECIFIED,
        GIT,
        SEMVER,
        ECOSYSTEM
    }
    
    /**
     * Default: "UNSPECIFIED"
     * Enum: "UNSPECIFIED" "GIT" "SEMVER" "ECOSYSTEM"
     * Type of the version information.
     */
    OsvRangeType type;
    
    /**
     * Required if type is GIT. 
     * The publicly accessible URL of the repo that can be directly passed to clone commands.
     */
    String repo;
    
    /**
     * Required. Version event information.
     */
    List<OsvEvent> events;
    
    /**
     * Required empty constructor
     */
    public OsvRange() {
        
    }

    /**
     * @return the type
     */
    public OsvRangeType getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(OsvRangeType type) {
        this.type = type;
    }

    /**
     * @return the repo
     */
    public String getRepo() {
        return repo;
    }

    /**
     * @param repo the repo to set
     */
    public void setRepo(String repo) {
        this.repo = repo;
    }

    /**
     * @return the events
     */
    public List<OsvEvent> getEvents() {
        return events;
    }

    /**
     * @param events the events to set
     */
    public void setEvents(List<OsvEvent> events) {
        this.events = events;
    }

}
