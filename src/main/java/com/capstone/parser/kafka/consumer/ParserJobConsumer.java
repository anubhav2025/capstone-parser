package com.capstone.parser.kafka.consumer;

import com.capstone.parser.dto.ack.ParseAcknowledgement;
import com.capstone.parser.dto.ack.payload.AcknowledgementEventPayload;
import com.capstone.parser.dto.event.ParseRequestEvent;
import com.capstone.parser.dto.event.payload.ParseRequestEventPayload;
import com.capstone.parser.enums.ToolTypes;
import com.capstone.parser.model.Tenant;
import com.capstone.parser.repository.TenantRepository;
import com.capstone.parser.service.AcknowledgementProducerService;
import com.capstone.parser.service.processor.CodeScanJobProcessorService;
import com.capstone.parser.service.processor.DependabotScanJobProcessorService;
import com.capstone.parser.service.processor.SecretScanJobProcessorService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

@Component
public class ParserJobConsumer {

    private final CodeScanJobProcessorService codeScanJobProcessorService;
    private final DependabotScanJobProcessorService dependabotScanJobProcessorService;
    private final SecretScanJobProcessorService secretScanJobProcessorService;
    private final TenantRepository tenantRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AcknowledgementProducerService acknowledgementProducerService;

    public ParserJobConsumer(CodeScanJobProcessorService codeScanJobProcessorService,
                             DependabotScanJobProcessorService dependabotScanJobProcessorService,
                             SecretScanJobProcessorService secretScanJobProcessorService,
                             TenantRepository tenantRepository,
                             AcknowledgementProducerService acknowledgementProducerService) {
        this.codeScanJobProcessorService = codeScanJobProcessorService;
        this.dependabotScanJobProcessorService = dependabotScanJobProcessorService;
        this.secretScanJobProcessorService = secretScanJobProcessorService;
        this.tenantRepository = tenantRepository;
        this.acknowledgementProducerService = acknowledgementProducerService;
    }

    @KafkaListener(
        topics = "${parser.kafka.topic}",
        containerFactory = "kafkaListenerContainerFactory",
        groupId = "parser-consumer-group"
    )
    public void consumeParseEvent(@Payload String message) {
        try {
            // Deserialize JSON string into ParseRequestEvent
            ParseRequestEvent event = objectMapper.readValue(message, ParseRequestEvent.class);
            System.out.println("Received ParseRequestEvent eventId=" + event.getEventId() +
                    ", type=" + event.getType());
            ParseRequestEventPayload payload = event.getPayload();
            ToolTypes tool = payload.getTool();
            String tenantId = payload.getTenantId();
            String filePath = payload.getFilePath();

            Tenant tenant = tenantRepository.findByTenantId(tenantId);
            if (tenant == null) {
                System.err.println("Tenant not found for tenantId=" + tenantId);
                return;
            }
            String esIndex = tenant.getEsIndex();
            if (esIndex == null || esIndex.isBlank()) {
                System.err.println("No esIndex set for tenantId=" + tenantId);
                return;
            }

            switch (tool) {
                case CODE_SCAN:
                    codeScanJobProcessorService.processJob(filePath, esIndex);
                    break;
                case DEPENDABOT:
                    dependabotScanJobProcessorService.processJob(filePath, esIndex);
                    break;
                case SECRET_SCAN:
                    secretScanJobProcessorService.processJob(filePath, esIndex);
                    break;
                default:
                    System.err.println("Unknown tool type: " + tool);
                    break;
            }
            
            AcknowledgementEventPayload ackPayload = new AcknowledgementEventPayload(event.getEventId());
            ParseAcknowledgement parseAck = new ParseAcknowledgement(null, ackPayload);
            acknowledgementProducerService.publishAcknowledgement(parseAck);
            

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
