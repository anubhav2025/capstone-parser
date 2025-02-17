package com.capstone.parser.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.query_dsl.MatchQuery;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.core.SearchRequest;
import co.elastic.clients.elasticsearch.core.SearchResponse;

import com.capstone.parser.enums.ToolTypes;
import com.capstone.parser.model.Finding;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Service
public class DeDupService {

    private final ElasticsearchClient esClient;
    private final ElasticSearchService elasticSearchService;

    public DeDupService(ElasticsearchClient esClient, ElasticSearchService elasticSearchService) {
        this.esClient = esClient;
        this.elasticSearchService = elasticSearchService;
    }

    /**
     * Fetch all existing documents from ES for the given tool type in the specified index,
     * so we can compare them with incoming alerts for de-dup.
     */
    public Map<String, Finding> fetchExistingDocsByTool(ToolTypes toolType, String esIndex) throws IOException {
        Query toolTypeQuery = MatchQuery.of(t -> t
            .field("toolType")
            .query(toolType.toString())
        )._toQuery();

        SearchRequest searchReq = SearchRequest.of(s -> s
            .index(esIndex)      // dynamic index
            .query(toolTypeQuery)
            .size(10_000)        // adapt if needed
        );

        SearchResponse<Finding> searchResp = esClient.search(searchReq, Finding.class);

        Map<String, Finding> existingMap = new HashMap<>();
        searchResp.hits().hits().forEach(hit -> {
            Finding existing = hit.source();
            if (existing != null) {
                String hash = computeHashForFinding(existing);
                existingMap.put(hash, existing);
            }
        });

        return existingMap;
    }

    /**
     * Compute a hash for a Finding by combining:
     *   - finding.getTitle()
     *   - optional "number" from finding.getToolAdditionalProperties()
     */
    public String computeHashForFinding(Finding f) {
        String title = f.getTitle() != null ? f.getTitle() : "";
        String number = "";
        if (f.getToolAdditionalProperties() != null) {
            Object numberObj = f.getToolAdditionalProperties().get("number");
            if (numberObj != null) {
                number = numberObj.toString();
            }
        }
        return md5(title + "|" + number);
    }

    /**
     * Check if an incoming finding differs (severity or state) from the existing doc.
     */
    public boolean isUpdated(Finding incoming, Finding existing) {
        if (!Objects.equals(incoming.getSeverity(), existing.getSeverity())) {
            return true;
        }
        if (!Objects.equals(incoming.getState(), existing.getState())) {
            return true;
        }
        return false;
    }

    /**
     * Overwrite an existing doc in ES by reusing the same _id, but in the specified index.
     */
    public void updateInES(Finding incoming, Finding existing, String esIndex) {
        incoming.setId(existing.getId());
        elasticSearchService.saveFinding(incoming, esIndex);
    }

    private String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not found", e);
        }
    }
}
