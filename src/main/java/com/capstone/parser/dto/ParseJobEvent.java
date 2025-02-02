package com.capstone.parser.dto;

public class ParseJobEvent {

    // e.g. "code-scan", "dependabot", "secret-scan"
    private String type;

    // path to JSON file containing alerts
    private String scanFilePath;

    // Getters and Setters
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }

    public String getScanFilePath() {
        return scanFilePath;
    }
    public void setScanFilePath(String scanFilePath) {
        this.scanFilePath = scanFilePath;
    }
}
