package com.capstone.parser.service.processor;

import com.capstone.parser.enums.ToolTypes;
import com.capstone.parser.model.*;
import com.capstone.parser.service.DeDupService;
import com.capstone.parser.service.ElasticSearchService;
import com.capstone.parser.service.StateSeverityMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.File;
import java.time.Instant;
import java.util.*;

@Service
public class CodeScanJobProcessorService implements ScanJobProcessorService {

    private final ElasticSearchService elasticSearchService;
    private final ObjectMapper objectMapper;
    private final DeDupService deDupService;

    public CodeScanJobProcessorService(ElasticSearchService elasticSearchService,
                                       ObjectMapper objectMapper,
                                       DeDupService deDupService) {
        this.elasticSearchService = elasticSearchService;
        this.objectMapper = objectMapper;
        this.deDupService = deDupService;
    }

    @Override
    public void processJob(String filePath, String esIndex) throws Exception {
        // 1) Load existing docs for CODE_SCAN from the given ES index
        Map<String, Finding> existingMap = deDupService.fetchExistingDocsByTool(
            ToolTypes.CODE_SCAN, esIndex
        );

        // 2) Parse the JSON array from the file
        List<Map<String, Object>> alerts = objectMapper.readValue(
            new File(filePath),
            new TypeReference<List<Map<String, Object>>>() {}
        );

        // 3) For each alert => map => deduplicate => save or skip
        for (Map<String, Object> alert : alerts) {
            Finding newFinding = mapAlertToFinding(alert);

            String newHash = deDupService.computeHashForFinding(newFinding);
            Finding existing = existingMap.get(newHash);
            if (existing == null) {
                // => new doc
                String now = Instant.now().toString();
                newFinding.setCreatedAt(now);
                newFinding.setUpdatedAt(now);

                // Save to the target index
                elasticSearchService.saveFinding(newFinding, esIndex);
                existingMap.put(newHash, newFinding);
            } else {
                // => deduplicate => check if updated
                boolean updated = deDupService.isUpdated(newFinding, existing);
                if (updated) {
                    // Preserve original createdAt
                    newFinding.setCreatedAt(existing.getCreatedAt());
                    newFinding.setUpdatedAt(Instant.now().toString());

                    // Update in ES
                    deDupService.updateInES(newFinding, existing, esIndex);
                    existingMap.put(newHash, newFinding);
                } else {
                    // => skip
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private Finding mapAlertToFinding(Map<String, Object> alert) {
        // Similar to your original logic
        String uniqueId = UUID.randomUUID().toString();

        String ghState = (String) alert.get("state");
        String url = (String) alert.get("url");
        String dismissedReason = (String) alert.get("dismissed_reason");

        Map<String, Object> rule = (Map<String, Object>) alert.get("rule");
        String title = null;
        String desc = null;
        String ghSeverity = null;
        String suggestions = null;
        String ruleId = null;

        if (rule != null) {
            title = (String) rule.get("name");
            desc = (String) rule.get("full_description");
            ghSeverity = (String) rule.get("security_severity_level");
            if (ghSeverity == null) {
                ghSeverity = (String) rule.get("severity");
            }
            suggestions = (String) rule.get("help");
            ruleId = (String) rule.get("id");
        }

        // cwes
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

        FindingState internalState = StateSeverityMapper.mapGitHubState(ghState, dismissedReason);
        FindingSeverity internalSeverity = StateSeverityMapper.mapGitHubSeverity(ghSeverity);

        Finding finding = new Finding();
        finding.setId(uniqueId);
        finding.setTitle(title);
        finding.setDesc(desc);
        finding.setSeverity(internalSeverity);
        finding.setState(internalState);
        finding.setUrl(url);
        finding.setToolType(ToolTypes.CODE_SCAN);
        finding.setCve(null);
        finding.setCwes(cwes);
        finding.setCvss(null);
        finding.setType(ruleId);
        finding.setSuggestions(suggestions);
        finding.setFilePath(filePath);
        finding.setComponentName(null);
        finding.setComponentVersion(null);
        finding.setTicketId(null);

        // store entire alert
        finding.setToolAdditionalProperties(alert);

        return finding;
    }
}
