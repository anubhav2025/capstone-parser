package com.capstone.parser.service.processor;

import com.capstone.parser.model.*;
import com.capstone.parser.service.ElasticSearchService;
import com.capstone.parser.service.StateSeverityMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.*;

@Service
public class CodeScanJobProcessorService implements ScanJobProcessorService {

    private final ElasticSearchService elasticSearchService;
    private final ObjectMapper objectMapper;

    public CodeScanJobProcessorService(ElasticSearchService elasticSearchService,
                                       ObjectMapper objectMapper) {
        this.elasticSearchService = elasticSearchService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void processJob(String filePath) throws Exception {
        // JSON file is an array of alerts
        List<Map<String, Object>> alerts = objectMapper.readValue(
                new File(filePath),
                new TypeReference<List<Map<String, Object>>>() {}
        );

        for (Map<String, Object> alert : alerts) {
            Finding finding = mapAlertToFinding(alert);
            elasticSearchService.saveFinding(finding);
        }
    }

    @SuppressWarnings("unchecked")
    private Finding mapAlertToFinding(Map<String, Object> alert) {
        // Generate a unique ID for each document
        String uniqueId = UUID.randomUUID().toString();

        String ghState = (String) alert.get("state");
        String url = (String) alert.get("url");

        Map<String, Object> rule = (Map<String, Object>) alert.get("rule");
        String title = null;
        String desc = null;
        String ghSeverity = null;
        String suggestions = null;
        String ruleId = null;

        if (rule != null) {
            title = (String) rule.get("name");
            desc = (String) rule.get("full_description");
            // GH severity is "security_severity_level" or "severity"
            ghSeverity = (String) rule.get("security_severity_level");
            if (ghSeverity == null) {
                ghSeverity = (String) rule.get("severity");
            }
            suggestions = (String) rule.get("help");
            ruleId = (String) rule.get("id");
        }

        // cwes => from rule.tags if any contain "cwe/"
        List<String> cwes = new ArrayList<>();
        if (rule != null && rule.get("tags") instanceof List) {
            List<String> tags = (List<String>) rule.get("tags");
            for (String tag : tags) {
                if (tag.contains("cwe/")) {
                    cwes.add(tag);
                }
            }
        }

        // location path
        String filePath = null;
        Map<String, Object> mostRecentInstance = (Map<String, Object>) alert.get("most_recent_instance");
        if (mostRecentInstance != null) {
            Map<String, Object> location = (Map<String, Object>) mostRecentInstance.get("location");
            if (location != null) {
                filePath = (String) location.get("path");
            }
        }

        // dismissed reason for mapping
        String dismissedReason = (String) alert.get("dismissed_reason");

        // Map GH state -> internal
        FindingState internalState = StateSeverityMapper.mapGitHubState(ghState, dismissedReason);
        FindingSeverity internalSeverity = StateSeverityMapper.mapGitHubSeverity(ghSeverity);

        Finding finding = new Finding();
        finding.setId(uniqueId);
        finding.setTitle(title);
        finding.setDesc(desc);
        finding.setSeverity(internalSeverity);
        finding.setState(internalState);

        finding.setUrl(url);
        finding.setToolType(ScanToolType.CODE_SCAN);
        finding.setCve(null); // Usually no CVE in code-scan
        finding.setCwes(cwes);
        finding.setCvss(null); // Not typically provided
        finding.setType(ruleId); // e.g. "js/template-object-injection"
        finding.setSuggestions(suggestions);
        finding.setFilePath(filePath);
        finding.setComponentName(null);
        finding.setComponentVersion(null);

        // Put entire alert in toolAdditionalProperties
        finding.setToolAdditionalProperties(alert);

        return finding;
    }
}
