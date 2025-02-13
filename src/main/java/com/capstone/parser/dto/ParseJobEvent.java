package com.capstone.parser.dto;

public class ParseJobEvent {

    // e.g. "codescan", "dependabot", "secretscan"
    private String toolName;

    // path to JSON file containing alerts
    private String scanFilePath;

    // The Elasticsearch index to store data for this tenant
    private String esIndex;

    public ParseJobEvent() {
    }

    public ParseJobEvent(String toolName, String scanFilePath, String esIndex) {
        this.toolName = toolName;
        this.scanFilePath = scanFilePath;
        this.esIndex = esIndex;
    }

    // Getters & Setters

    public String getToolName() {
        return toolName;
    }
    public void setToolName(String toolName) {
        this.toolName = toolName;
    }

    public String getScanFilePath() {
        return scanFilePath;
    }
    public void setScanFilePath(String scanFilePath) {
        this.scanFilePath = scanFilePath;
    }

    public String getEsIndex() {
        return esIndex;
    }
    public void setEsIndex(String esIndex) {
        this.esIndex = esIndex;
    }
}
