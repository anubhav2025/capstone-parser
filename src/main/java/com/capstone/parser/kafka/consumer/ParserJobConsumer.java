package com.capstone.parser.kafka.consumer;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import com.capstone.parser.config.ApplicationProperties;
import com.capstone.parser.dto.ParseJobEvent;
import com.capstone.parser.service.processor.CodeScanJobProcessorService;
import com.capstone.parser.service.processor.DependabotScanJobProcessorService;
import com.capstone.parser.service.processor.SecretScanJobProcessorService;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class ParserJobConsumer {

    private final ObjectMapper objectMapper;
    private final CodeScanJobProcessorService codeScanJobProcessorService;
    private final DependabotScanJobProcessorService dependabotScanJobProcessorService;
    private final SecretScanJobProcessorService secretScanJobProcessorService;
    private final ApplicationProperties appProperties;

    public ParserJobConsumer(ObjectMapper objectMapper,
                             CodeScanJobProcessorService codeScanJobProcessorService,
                             DependabotScanJobProcessorService dependabotScanJobProcessorService,
                             SecretScanJobProcessorService secretScanJobProcessorService,
                             ApplicationProperties appProperties) {
        this.objectMapper = objectMapper;
        this.codeScanJobProcessorService = codeScanJobProcessorService;
        this.dependabotScanJobProcessorService = dependabotScanJobProcessorService;
        this.secretScanJobProcessorService = secretScanJobProcessorService;
        this.appProperties = appProperties;
    }

    @KafkaListener(
        topics = "#{applicationProperties.topic}",  // SpEL to read parser.kafka.topic
        groupId = "${spring.kafka.consumer.group-id}"
    )
    public void consume(String message) {
        try {
            System.out.println("Received ParseJobEvent: " + message);
            ParseJobEvent event = objectMapper.readValue(message, ParseJobEvent.class);

            String toolName = event.getToolName();       // "codescan", "dependabot", "secretscan"
            String filePath = event.getScanFilePath();  // e.g. "/path/to/scan-result.json"
            String esIndex = event.getEsIndex();        // e.g. "tenant-123-findings"

            switch (toolName.toLowerCase()) {
                case "codescan":
                    codeScanJobProcessorService.processJob(filePath, esIndex);
                    break;
                case "dependabot":
                    dependabotScanJobProcessorService.processJob(filePath, esIndex);
                    break;
                case "secretscan":
                    secretScanJobProcessorService.processJob(filePath, esIndex);
                    break;
                default:
                    System.err.println("Unknown tool name: " + toolName);
                    break;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
