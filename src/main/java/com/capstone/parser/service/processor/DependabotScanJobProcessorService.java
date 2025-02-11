package com.capstone.parser.service.processor;

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
public class DependabotScanJobProcessorService implements ScanJobProcessorService {

    private final ElasticSearchService elasticSearchService;
    private final ObjectMapper objectMapper;
    private final DeDupService deDupService;

    public DependabotScanJobProcessorService(ElasticSearchService elasticSearchService,
                                             ObjectMapper objectMapper,
                                             DeDupService deDupService) {
        this.elasticSearchService = elasticSearchService;
        this.objectMapper = objectMapper;
        this.deDupService = deDupService;
    }

    @Override
    public void processJob(String filePath) throws Exception {
        // 1) Load existing docs once for DEPENDABOT
        Map<String, Finding> existingMap = deDupService.fetchExistingDocsByTool(ScanToolType.DEPENDABOT);

        // 2) Parse the file (alerts array)
        List<Map<String, Object>> alerts = objectMapper.readValue(
                new File(filePath),
                new TypeReference<List<Map<String, Object>>>() {}
        );

        // 3) For each alert, map to Finding
        for (Map<String, Object> alert : alerts) {
            Finding newFinding = mapAlertToFinding(alert);
            // System.out.println("hewllo");
            // System.out.println(newFinding.toString());

            // 4) Compute hash
            String newHash = deDupService.computeHashForFinding(newFinding);

            // 5) Check if existing doc is in memory
            Finding existing = existingMap.get(newHash);
            if (existing == null) {
                // => brand new doc
                String now = Instant.now().toString();
                newFinding.setCreatedAt(now);
                newFinding.setUpdatedAt(now);

                elasticSearchService.saveFinding(newFinding);
                existingMap.put(newHash, newFinding);
            } else {
                // => matching doc found => check if updated
                boolean updated = deDupService.isUpdated(newFinding, existing);
                if (updated) {
                    // Keep the original createdAt, update updatedAt
                    newFinding.setCreatedAt(existing.getCreatedAt());
                    newFinding.setUpdatedAt(Instant.now().toString());

                    deDupService.updateInES(newFinding, existing);
                    existingMap.put(newHash, newFinding); 
                } else {
                    // => truly redundant => skip
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private Finding mapAlertToFinding(Map<String, Object> alert) {
        String uniqueId = UUID.randomUUID().toString();

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

            // cvss
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

        FindingState internalState = StateSeverityMapper.mapGitHubState(ghState, dismissedReason);
        FindingSeverity internalSeverity = StateSeverityMapper.mapGitHubSeverity(ghSeverity);

        Finding finding = new Finding();
        finding.setId(uniqueId);
        finding.setTitle(summary);         // <--- Title used for hashing
        finding.setDesc(description);
        finding.setSeverity(internalSeverity);
        finding.setState(internalState);
        finding.setUrl(url);
        finding.setToolType(ScanToolType.DEPENDABOT);
        finding.setCve(cve);
        finding.setCwes(cwes);
        finding.setCvss(cvss);
        finding.setType("dependabot");
        finding.setSuggestions(null);
        finding.setFilePath(filePath);
        finding.setComponentName(componentName);
        finding.setComponentVersion(null);
        finding.setToolAdditionalProperties(alert); // contains "number"

        return finding;
    }
}
