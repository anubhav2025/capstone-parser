package com.capstone.parser.service.processor;

import com.capstone.parser.enums.ToolTypes;
import com.capstone.parser.model.Finding;
import com.capstone.parser.service.DeDupService;
import com.capstone.parser.service.ElasticSearchService;
import com.capstone.parser.service.ParserContextHolder;
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
        // Load existing CODE_SCAN findings from ES
        Map<String, Finding> existingMap =
            deDupService.fetchExistingDocsByTool(ToolTypes.CODE_SCAN, esIndex);

        // Parse the JSON array from the file
        List<Map<String, Object>> alerts = objectMapper.readValue(
            new File(filePath),
            new TypeReference<List<Map<String, Object>>>() {}
        );

        // Instead of only changed findings, we collect all processed finding IDs.
        List<String> allFindingIds = new ArrayList<>();

        for (Map<String, Object> alert : alerts) {
            Finding newFinding = mapAlertToFinding(alert);
            String newHash = deDupService.computeHashForFinding(newFinding);
            Finding existing = existingMap.get(newHash);

            if (existing == null) {
                // New finding: save it and add its ID.
                String now = Instant.now().toString();
                newFinding.setCreatedAt(now);
                newFinding.setUpdatedAt(now);
                elasticSearchService.saveFinding(newFinding, esIndex);
                existingMap.put(newHash, newFinding);
                allFindingIds.add(newFinding.getId());
            } else {
                // Finding exists.
                if (deDupService.isUpdated(newFinding, existing)) {
                    newFinding.setCreatedAt(existing.getCreatedAt());
                    newFinding.setUpdatedAt(Instant.now().toString());
                    deDupService.updateInES(newFinding, existing, esIndex);
                    existingMap.put(newHash, newFinding);
                    allFindingIds.add(existing.getId());
                } else {
                    // No update; add the existing finding's ID.
                    allFindingIds.add(existing.getId());
                }
            }
        }
        // Force an ES refresh so all findings become searchable immediately.
        elasticSearchService.refreshIndex(esIndex);

        // Store all finding IDs in the ThreadLocal context.
        ParserContextHolder.setChangedFindingIds(allFindingIds);
    }

    @SuppressWarnings("unchecked")
    private Finding mapAlertToFinding(Map<String, Object> alert) {
        // Example mapping logic for CodeScan alerts.
        String uniqueId = UUID.randomUUID().toString();
        String ghState = (String) alert.get("state");
        String url = (String) alert.get("url");
        String dismissedReason = (String) alert.get("dismissed_reason");

        Map<String, Object> rule = (Map<String, Object>) alert.get("rule");
        String title = rule != null ? (String) rule.get("name") : null;
        String desc = rule != null ? (String) rule.get("full_description") : null;
        String ghSeverity = rule != null ? (String) rule.get("security_severity_level") : null;
        if (ghSeverity == null && rule != null) {
            ghSeverity = (String) rule.get("severity");
        }
        String suggestions = rule != null ? (String) rule.get("help") : null;
        String ruleId = rule != null ? (String) rule.get("id") : null;

        List<String> cwes = new ArrayList<>();
        if (rule != null && rule.get("tags") instanceof List) {
            List<String> tags = (List<String>) rule.get("tags");
            for (String tag : tags) {
                if (tag.contains("cwe/")) {
                    cwes.add(tag);
                }
            }
        }

        String filePath = null;
        Map<String, Object> mostRecentInstance = (Map<String, Object>) alert.get("most_recent_instance");
        if (mostRecentInstance != null) {
            Map<String, Object> location = (Map<String, Object>) mostRecentInstance.get("location");
            if (location != null) {
                filePath = (String) location.get("path");
            }
        }

        // Map GitHub state to internal state
        var internalState = StateSeverityMapper.mapGitHubState(ghState, dismissedReason);
        var internalSeverity = StateSeverityMapper.mapGitHubSeverity(ghSeverity);

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

        finding.setToolAdditionalProperties(alert);
        return finding;
    }
}
