package com.capstone.parser.kafka.consumer;

import com.capstone.parser.dto.ack.ParseAcknowledgement;
import com.capstone.parser.dto.ack.payload.AcknowledgementEventPayload;
import com.capstone.parser.dto.event.ParseRequestEvent;
import com.capstone.parser.dto.event.RunbookJobEvent;
import com.capstone.parser.dto.event.payload.ParseRequestEventPayload;
import com.capstone.parser.dto.event.payload.RunbookJobEventPayload;
import com.capstone.parser.enums.ToolTypes;
import com.capstone.parser.model.Tenant;
import com.capstone.parser.repository.TenantRepository;
import com.capstone.parser.service.AcknowledgementProducerService;
import com.capstone.parser.service.ElasticSearchService;
import com.capstone.parser.service.JfcProducerService;
import com.capstone.parser.service.ParserContextHolder;
import com.capstone.parser.service.processor.CodeScanJobProcessorService;
import com.capstone.parser.service.processor.DependabotScanJobProcessorService;
import com.capstone.parser.service.processor.SecretScanJobProcessorService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
public class ParserJobConsumer {

    private final CodeScanJobProcessorService codeScanJobProcessorService;
    private final DependabotScanJobProcessorService dependabotScanJobProcessorService;
    private final SecretScanJobProcessorService secretScanJobProcessorService;
    private final TenantRepository tenantRepository;
    private final AcknowledgementProducerService acknowledgementProducerService;
    private final JfcProducerService jfcProducerService;
    private final ElasticSearchService elasticSearchService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public ParserJobConsumer(CodeScanJobProcessorService codeScanJobProcessorService,
                             DependabotScanJobProcessorService dependabotScanJobProcessorService,
                             SecretScanJobProcessorService secretScanJobProcessorService,
                             TenantRepository tenantRepository,
                             AcknowledgementProducerService acknowledgementProducerService,
                             JfcProducerService jfcProducerService, ElasticSearchService elasticSearchService) {
        this.codeScanJobProcessorService = codeScanJobProcessorService;
        this.dependabotScanJobProcessorService = dependabotScanJobProcessorService;
        this.secretScanJobProcessorService = secretScanJobProcessorService;
        this.tenantRepository = tenantRepository;
        this.acknowledgementProducerService = acknowledgementProducerService;
        this.jfcProducerService = jfcProducerService;
        this.elasticSearchService = elasticSearchService;
    }

    @KafkaListener(
        topics = "${parser.kafka.topic}",
        containerFactory = "kafkaListenerContainerFactory",
        groupId = "parser-consumer-group"
    )
    public void consumeParseEvent(@Payload String message) {
        try {
            ParseRequestEvent event = objectMapper.readValue(message, ParseRequestEvent.class);
            ParseRequestEventPayload payload = event.getPayload();
            ToolTypes tool = payload.getTool();
            String tenantId = payload.getTenantId();
            String filePath = payload.getFilePath();

            Tenant tenant = tenantRepository.findByTenantId(tenantId);
            if (tenant == null) {
                System.err.println("Tenant not found for tenantId=" + tenantId);
                return;
            }

            switch (tool) {
                case CODE_SCAN:
                    codeScanJobProcessorService.processJob(filePath, tenant.getEsIndex());
                    break;
                case DEPENDABOT:
                    dependabotScanJobProcessorService.processJob(filePath, tenant.getEsIndex());
                    break;
                case SECRET_SCAN:
                    secretScanJobProcessorService.processJob(filePath, tenant.getEsIndex());
                    break;
                default:
                    System.err.println("Unknown tool type: " + tool);
                    break;
            }

            // After processing, gather changed IDs
            List<String> allFindingIds = ParserContextHolder.getChangedFindingIds();
            if (allFindingIds != null && !allFindingIds.isEmpty()) {
                RunbookJobEventPayload runbookPayload = new RunbookJobEventPayload(tenantId, allFindingIds);
                RunbookJobEvent runbookEvent = new RunbookJobEvent(runbookPayload);
                runbookEvent.setEventId(UUID.randomUUID().toString());
                jfcProducerService.publishRunbookJob(runbookEvent);
            }

            // Send parse ack
            AcknowledgementEventPayload ackPayload = new AcknowledgementEventPayload(event.getEventId());
            ParseAcknowledgement parseAck = new ParseAcknowledgement(null, ackPayload);
            acknowledgementProducerService.publishAcknowledgement(parseAck);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            ParserContextHolder.clear();
        }
    }
}
