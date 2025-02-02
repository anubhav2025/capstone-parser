package com.capstone.parser.model;

import java.util.List;
import java.util.Map;

public class Finding {

    private String id;
    private String title;
    private String desc;
    private FindingSeverity severity;
    private FindingState state;
    private String url;
    private ScanToolType toolType;

    private String cve;
    private List<String> cwes;
    private String cvss;

    private String type;

    private String suggestions;

    private String filePath;

    private String componentName;
    private String componentVersion;

    private Map<String, Object> toolAdditionalProperties;

    // Getters and setters ...
    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }
    public void setTitle(String title) {
        this.title = title;
    }

    public String getDesc() {
        return desc;
    }
    public void setDesc(String desc) {
        this.desc = desc;
    }

    public FindingSeverity getSeverity() {
        return severity;
    }
    public void setSeverity(FindingSeverity severity) {
        this.severity = severity;
    }

    public FindingState getState() {
        return state;
    }
    public void setState(FindingState state) {
        this.state = state;
    }

    public String getUrl() {
        return url;
    }
    public void setUrl(String url) {
        this.url = url;
    }

    public ScanToolType getToolType() {
        return toolType;
    }
    public void setToolType(ScanToolType toolType) {
        this.toolType = toolType;
    }

    public String getCve() {
        return cve;
    }
    public void setCve(String cve) {
        this.cve = cve;
    }

    public List<String> getCwes() {
        return cwes;
    }
    public void setCwes(List<String> cwes) {
        this.cwes = cwes;
    }

    public String getCvss() {
        return cvss;
    }
    public void setCvss(String cvss) {
        this.cvss = cvss;
    }

    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }

    public String getSuggestions() {
        return suggestions;
    }
    public void setSuggestions(String suggestions) {
        this.suggestions = suggestions;
    }

    public String getFilePath() {
        return filePath;
    }
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getComponentName() {
        return componentName;
    }
    public void setComponentName(String componentName) {
        this.componentName = componentName;
    }

    public String getComponentVersion() {
        return componentVersion;
    }
    public void setComponentVersion(String componentVersion) {
        this.componentVersion = componentVersion;
    }

    public Map<String, Object> getToolAdditionalProperties() {
        return toolAdditionalProperties;
    }
    public void setToolAdditionalProperties(Map<String, Object> toolAdditionalProperties) {
        this.toolAdditionalProperties = toolAdditionalProperties;
    }
}
