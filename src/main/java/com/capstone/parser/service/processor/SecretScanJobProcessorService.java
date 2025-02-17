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
public class SecretScanJobProcessorService implements ScanJobProcessorService {

    private final ElasticSearchService elasticSearchService;
    private final ObjectMapper objectMapper;
    private final DeDupService deDupService;

    public SecretScanJobProcessorService(ElasticSearchService elasticSearchService,
                                         ObjectMapper objectMapper,
                                         DeDupService deDupService) {
        this.elasticSearchService = elasticSearchService;
        this.objectMapper = objectMapper;
        this.deDupService = deDupService;
    }

    @Override
    public void processJob(String filePath, String esIndex) throws Exception {
        // 1) Load existing docs for SECRET_SCAN from given index
        Map<String, Finding> existingMap = deDupService.fetchExistingDocsByTool(
            ToolTypes.SECRET_SCAN, esIndex
        );

        // 2) Parse the file
        List<Map<String, Object>> alerts = objectMapper.readValue(
            new File(filePath),
            new TypeReference<List<Map<String, Object>>>() {}
        );

        // 3) For each alert => map => dedup => save or skip
        for (Map<String, Object> alert : alerts) {
            Finding newFinding = mapAlertToFinding(alert);

            String newHash = deDupService.computeHashForFinding(newFinding);
            Finding existing = existingMap.get(newHash);
            if (existing == null) {
                // => new doc
                String now = Instant.now().toString();
                newFinding.setCreatedAt(now);
                newFinding.setUpdatedAt(now);

                elasticSearchService.saveFinding(newFinding, esIndex);
                existingMap.put(newHash, newFinding);
            } else {
                // => check if updated
                boolean updated = deDupService.isUpdated(newFinding, existing);
                if (updated) {
                    newFinding.setCreatedAt(existing.getCreatedAt());
                    newFinding.setUpdatedAt(Instant.now().toString());

                    deDupService.updateInES(newFinding, existing, esIndex);
                    existingMap.put(newHash, newFinding);
                } else {
                    // skip
                }
            }
        }
    }

    private Finding mapAlertToFinding(Map<String, Object> alert) {
        String uniqueId = UUID.randomUUID().toString();

        String ghState = (String) alert.get("state");
        String url = (String) alert.get("url");
        String secretTypeDisplay = (String) alert.get("secret_type_display_name");
        String secretType = (String) alert.get("secret_type");

        // Map GH state
        FindingState internalState = StateSeverityMapper.mapGitHubState(ghState, null);
        // GH has no explicit severity => default to HIGH, etc.
        FindingSeverity internalSeverity = StateSeverityMapper.mapGitHubSeverity(null);

        Finding finding = new Finding();
        finding.setId(uniqueId);
        finding.setTitle(secretTypeDisplay);
        finding.setDesc("Secret found in repo (type: " + secretType + ")");
        finding.setSeverity(internalSeverity);
        finding.setState(internalState);
        finding.setUrl(url);
        finding.setToolType(ToolTypes.SECRET_SCAN);
        finding.setCve(null);
        finding.setCwes(new ArrayList<>());
        finding.setCvss(null);
        finding.setType(secretType);
        finding.setSuggestions("Rotate or revoke this secret immediately");
        finding.setFilePath(null);
        finding.setComponentName(null);
        finding.setComponentVersion(null);

        // store entire raw alert
        finding.setToolAdditionalProperties(alert);

        return finding;
    }
}
