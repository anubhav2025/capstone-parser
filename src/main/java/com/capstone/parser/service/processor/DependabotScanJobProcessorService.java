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
    public void processJob(String filePath, String esIndex) throws Exception {
        // Load existing Dependabot findings from ES
        Map<String, Finding> existingMap =
            deDupService.fetchExistingDocsByTool(ToolTypes.DEPENDABOT, esIndex);

        List<Map<String, Object>> alerts = objectMapper.readValue(
            new File(filePath),
            new TypeReference<List<Map<String, Object>>>() {}
        );

        List<String> allFindingIds = new ArrayList<>();

        for (Map<String, Object> alert : alerts) {
            Finding newFinding = mapAlertToFinding(alert);
            String newHash = deDupService.computeHashForFinding(newFinding);
            Finding existing = existingMap.get(newHash);

            if (existing == null) {
                String now = Instant.now().toString();
                newFinding.setCreatedAt(now);
                newFinding.setUpdatedAt(now);
                elasticSearchService.saveFinding(newFinding, esIndex);
                existingMap.put(newHash, newFinding);
                allFindingIds.add(newFinding.getId());
            } else {
                if (deDupService.isUpdated(newFinding, existing)) {
                    newFinding.setCreatedAt(existing.getCreatedAt());
                    newFinding.setUpdatedAt(Instant.now().toString());
                    deDupService.updateInES(newFinding, existing, esIndex);
                    existingMap.put(newHash, newFinding);
                    allFindingIds.add(existing.getId());
                } else {
                    allFindingIds.add(existing.getId());
                }
            }
        }

        elasticSearchService.refreshIndex(esIndex);
        ParserContextHolder.setChangedFindingIds(allFindingIds);
    }

    @SuppressWarnings("unchecked")
    private Finding mapAlertToFinding(Map<String, Object> alert) {
        String uniqueId = UUID.randomUUID().toString();
        String ghState = (String) alert.get("state");
        String url = (String) alert.get("url");
        String dismissedReason = (String) alert.get("dismissed_reason");

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

            if (securityAdvisory.get("cwes") instanceof List) {
                List<Map<String, Object>> cweList = (List<Map<String, Object>>) securityAdvisory.get("cwes");
                for (Map<String, Object> cweObj : cweList) {
                    String cweId = (String) cweObj.get("cwe_id");
                    if (cweId != null) cwes.add(cweId);
                }
            }

            Map<String, Object> cvssObj = (Map<String, Object>) securityAdvisory.get("cvss");
            if (cvssObj != null && cvssObj.get("score") != null) {
                cvss = String.valueOf(cvssObj.get("score"));
            }
        }

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

        var internalState = StateSeverityMapper.mapGitHubState(ghState, dismissedReason);
        var internalSeverity = StateSeverityMapper.mapGitHubSeverity(ghSeverity);

        Finding finding = new Finding();
        finding.setId(uniqueId);
        finding.setTitle(summary);
        finding.setDesc(description);
        finding.setSeverity(internalSeverity);
        finding.setState(internalState);
        finding.setUrl(url);
        finding.setToolType(ToolTypes.DEPENDABOT);
        finding.setCve(cve);
        finding.setCwes(cwes);
        finding.setCvss(cvss);
        finding.setType("dependabot");
        finding.setSuggestions(null);
        finding.setFilePath(filePath);
        finding.setComponentName(componentName);
        finding.setComponentVersion(null);
        finding.setTicketId(null);
        finding.setToolAdditionalProperties(alert);
        return finding;
    }
}
