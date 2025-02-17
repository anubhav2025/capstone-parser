package com.capstone.parser.service;

import com.capstone.parser.dto.ack.Acknowledgement;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

/**
 * Produces a JSON-based acknowledgement (ParseAcknowledgement or ScanRequestAcknowledgement)
 * to the 'job-ack' topic, so JFC can update the job status.
 */
@Service
public class AcknowledgementProducerService {

    @Value("job-acknowledgement-topic")
    private String ackTopic;  // the topic name from your config

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    public AcknowledgementProducerService(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Publishes the given acknowledgement to the job_ack topic.
     * The 'ack' can be either a ParseAcknowledgement or ScanRequestAcknowledgement, 
     * or any other Acknowledgement<T>.
     */
    public void publishAcknowledgement(Acknowledgement<?> ack) {
        try {
            // Convert the Acknowledgement object to JSON
            String ackJson = objectMapper.writeValueAsString(ack);

            // Send to Kafka
            kafkaTemplate.send(ackTopic, ackJson)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        System.err.println("[AcknowledgementProducerService] Failed to send ack: " 
                            + ex.getMessage());
                    } else {
                        System.out.println("[AcknowledgementProducerService] Sent ack => " 
                            + ackTopic + " partition=" + result.getRecordMetadata().partition()
                            + " offset=" + result.getRecordMetadata().offset());
                    }
                });
        } catch (Exception e) {
            System.err.println("[AcknowledgementProducerService] Error serializing ack: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
