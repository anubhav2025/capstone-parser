package com.capstone.parser.service;

import com.capstone.parser.model.Finding;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.IndexRequest;
import co.elastic.clients.elasticsearch.core.IndexResponse;
import org.springframework.stereotype.Service;

@Service
public class ElasticSearchService {

    private final ElasticsearchClient esClient;

    public ElasticSearchService(ElasticsearchClient esClient) {
        this.esClient = esClient;
    }

    /**
     * Save the Finding document to the given ES index.
     */
    public void saveFinding(Finding finding, String esIndex) {
        try {
            IndexRequest<Finding> request = IndexRequest.of(builder ->
                builder.index(esIndex)
                       .id(finding.getId())
                       .document(finding)
            );
            IndexResponse response = esClient.index(request);
            System.out.println("Saved " + finding.getToolType() 
                + " doc to index=" + esIndex 
                + " with _id: " + response.id());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
