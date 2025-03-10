package com.capstone.parser.service;

import com.capstone.parser.dto.event.RunbookJobEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class JfcProducerService {

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    @Value("job_ingestion_topic")
    private String jfcTopic;  // The JFC ingestion topic name

    public JfcProducerService(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = new ObjectMapper();
    }

    public void publishRunbookJob(RunbookJobEvent event) {
        try {
            String json = objectMapper.writeValueAsString(event);
            kafkaTemplate.send(jfcTopic, json);
            System.out.println("[JfcProducerService] Published RUNBOOK_JOB => " + event.getEventId());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
