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
public class SecretScanJobProcessorService implements ScanJobProcessorService {

    private final ElasticSearchService elasticSearchService;
    private final ObjectMapper objectMapper;

    public SecretScanJobProcessorService(ElasticSearchService elasticSearchService,
                                         ObjectMapper objectMapper) {
        this.elasticSearchService = elasticSearchService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void processJob(String filePath) throws Exception {
        List<Map<String, Object>> alerts = objectMapper.readValue(
                new File(filePath),
                new TypeReference<List<Map<String, Object>>>() {}
        );

        for (Map<String, Object> alert : alerts) {
            Finding finding = mapAlertToFinding(alert);
            elasticSearchService.saveFinding(finding);
        }
    }

    private Finding mapAlertToFinding(Map<String, Object> alert) {
        String uniqueId = UUID.randomUUID().toString();

        String ghState = (String) alert.get("state");
        String url = (String) alert.get("url");

        String secretTypeDisplay = (String) alert.get("secret_type_display_name");
        String secretType = (String) alert.get("secret_type");

        // GH has no explicit severity for secrets, we define default = HIGH or CRITICAL
        FindingSeverity internalSeverity = StateSeverityMapper.mapGitHubSeverity(null);

        // Possibly "resolved" => "fixed"
        // "open" => "open"
        // "dismissed" => "suppressed"? 
        // etc. No "dismissed_reason" typically for secret scanning, but let's just pass null
        FindingState internalState = StateSeverityMapper.mapGitHubState(ghState, null);

        Finding finding = new Finding();
        finding.setId(uniqueId);
        finding.setTitle(secretTypeDisplay);
        finding.setDesc("Secret found in repo (type: " + secretType + ")");
        finding.setSeverity(internalSeverity);
        finding.setState(internalState);
        finding.setUrl(url);
        finding.setToolType(ScanToolType.SECRET_SCAN);
        finding.setCve(null);
        finding.setCwes(new ArrayList<>());
        finding.setCvss(null);
        finding.setType(secretType);
        finding.setSuggestions("Rotate or revoke this secret immediately");
        finding.setFilePath(null); 
        finding.setComponentName(null);
        finding.setComponentVersion(null);
        finding.setToolAdditionalProperties(alert);

        return finding;
    }
}
