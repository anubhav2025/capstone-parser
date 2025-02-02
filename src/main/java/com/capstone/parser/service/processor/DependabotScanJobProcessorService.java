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
public class DependabotScanJobProcessorService implements ScanJobProcessorService {

    private final ElasticSearchService elasticSearchService;
    private final ObjectMapper objectMapper;

    public DependabotScanJobProcessorService(ElasticSearchService elasticSearchService,
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

    @SuppressWarnings("unchecked")
    private Finding mapAlertToFinding(Map<String, Object> alert) {
        String uniqueId = UUID.randomUUID().toString();

        // parse top-level fields
        String ghState = (String) alert.get("state");
        String url = (String) alert.get("url");
        String dismissedReason = (String) alert.get("dismissed_reason");

        // security_advisory
        Map<String, Object> securityAdvisory = (Map<String, Object>) alert.get("security_advisory");
        String cve = null;
        String summary = null;
        String description = null;
        String ghSeverity = null;
        String cvss = null;
        List<String> cwes = new ArrayList<>();

        if (securityAdvisory != null) {
            cve = (String) securityAdvisory.get("cve_id");
            summary = (String) securityAdvisory.get("summary");
            description = (String) securityAdvisory.get("description");
            ghSeverity = (String) securityAdvisory.get("severity");

            // parse cwes
            if (securityAdvisory.get("cwes") instanceof List) {
                List<Map<String, Object>> cweList = (List<Map<String, Object>>) securityAdvisory.get("cwes");
                for (Map<String, Object> cweObj : cweList) {
                    String cweId = (String) cweObj.get("cwe_id");
                    if (cweId != null) {
                        cwes.add(cweId);
                    }
                }
            }

            // cvss -> might exist as "cvss.score"
            Map<String, Object> cvssObj = (Map<String, Object>) securityAdvisory.get("cvss");
            if (cvssObj != null && cvssObj.get("score") != null) {
                cvss = String.valueOf(cvssObj.get("score"));
            }
        }

        // dependency
        Map<String, Object> dependency = (Map<String, Object>) alert.get("dependency");
        String filePath = null;
        String componentName = null;
        if (dependency != null) {
            filePath = (String) dependency.get("manifest_path");
            Map<String, Object> pkg = (Map<String, Object>) dependency.get("package");
            if (pkg != null) {
                componentName = (String) pkg.get("name");
            }
        }

        // map GH states to internal
        FindingState internalState = StateSeverityMapper.mapGitHubState(ghState, dismissedReason);
        FindingSeverity internalSeverity = StateSeverityMapper.mapGitHubSeverity(ghSeverity);

        Finding finding = new Finding();
        finding.setId(uniqueId);
        finding.setTitle(summary);
        finding.setDesc(description);
        finding.setSeverity(internalSeverity);
        finding.setState(internalState);
        finding.setUrl(url);
        finding.setToolType(ScanToolType.DEPENDABOT);
        finding.setCve(cve);
        finding.setCwes(cwes);
        finding.setCvss(cvss);
        finding.setType("dependabot"); 
        finding.setSuggestions(null); // You could parse from "first_patched_version" etc.
        finding.setFilePath(filePath);
        finding.setComponentName(componentName);
        finding.setComponentVersion(null);
        finding.setToolAdditionalProperties(alert);

        return finding;
    }
}
