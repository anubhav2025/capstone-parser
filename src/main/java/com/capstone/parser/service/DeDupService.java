package com.capstone.parser.service;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import org.springframework.stereotype.Service;

import com.capstone.parser.model.Finding;
import com.capstone.parser.model.ScanToolType;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.query_dsl.MatchQuery;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch._types.query_dsl.TermQuery;
import co.elastic.clients.elasticsearch.core.SearchRequest;
import co.elastic.clients.elasticsearch.core.SearchResponse;

/**
 * A service to handle fetching existing docs and performing de-dup logic
 * for each incoming Finding.
 */
@Service
public class DeDupService {

    private final ElasticsearchClient esClient;
    private final ElasticSearchService elasticSearchService;

    public DeDupService(ElasticsearchClient esClient, ElasticSearchService elasticSearchService) {
        this.esClient = esClient;
        this.elasticSearchService = elasticSearchService;
    }

    /**
     * Fetch all existing documents from ES for the given tool type
     * so we can compare the incoming alerts to them.
     *
     * Return a Map: "hashValue -> existing Finding"
     */
    public Map<String, Finding> fetchExistingDocsByTool(ScanToolType toolType) throws IOException {
        // We'll query the "findings" index for doc with toolType == theGivenToolType
        Query toolTypeQuery = MatchQuery.of(t -> t
            .field("toolType")
            .query(toolType.toString())
        )._toQuery();

        // System.out.println(toolType.toString());
        SearchRequest searchReq = SearchRequest.of(s -> s
            .index("findings")
            .query(toolTypeQuery)
            .size(10_000) // adjust as needed
        );

        SearchResponse<Finding> searchResp = esClient.search(searchReq, Finding.class);

        // Build a map (hash -> existingFinding)
        Map<String, Finding> existingMap = new HashMap<>();
        searchResp.hits().hits().forEach(hit -> {
            Finding existing = hit.source();
            if (existing != null) {
                String hash = computeHashForFinding(existing);
                existingMap.put(hash, existing);
            }
        });

        // System.out.println("hello");
        // System.out.println(existingMap);

        return existingMap;
    }

    /**
     * Compute a hash for a Finding by combining:
     *   - finding.getTitle()
     *   - toolAdditionalProperties -> number
     */
    public String computeHashForFinding(Finding f) {
        String title = f.getTitle() != null ? f.getTitle() : "";
        String number = "";
        if (f.getToolAdditionalProperties() != null) {
            Object numberObj = f.getToolAdditionalProperties().get("number");
            number = numberObj != null ? numberObj.toString() : "";
        }

        return md5(title + "|" + number);
    }

    /**
     * Helper: MD5 a string
     */
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

    /**
     * Compare an incoming Finding vs. an existing one to see if it is an update.
     * Return true if updated (i.e. severity/state or other fields differ).
     * Return false if it is truly redundant (unchanged).
     */
    public boolean isUpdated(Finding incoming, Finding existing) {
        // Compare severity
        if (!Objects.equals(incoming.getSeverity(), existing.getSeverity())) {
            return true;
        }
        // Compare state
        if (!Objects.equals(incoming.getState(), existing.getState())) {
            return true;
        }
        // Add more fields if you want to treat them as "updated" triggers
        return false;
    }

    /**
     * Overwrite an existing doc in ES by reusing the same _id
     */
    public void updateInES(Finding incoming, Finding existing) {
        // Reuse existing doc's ID
        incoming.setId(existing.getId());
        // Then re-save
        elasticSearchService.saveFinding(incoming);
    }
}
