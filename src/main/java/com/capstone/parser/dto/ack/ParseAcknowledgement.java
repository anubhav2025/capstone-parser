package com.capstone.parser.dto.ack;

import java.util.UUID;

import com.capstone.parser.dto.ack.payload.AcknowledgementEventPayload;

public class ParseAcknowledgement implements Acknowledgement<AcknowledgementEventPayload> {

    private String acknowledgementId;
    private AcknowledgementEventPayload payload;

    public ParseAcknowledgement() { 
        // no-arg for deserialization
    }

    public ParseAcknowledgement(String acknowledgementId, AcknowledgementEventPayload payload) {
        this.acknowledgementId = (acknowledgementId == null || acknowledgementId.isEmpty())
            ? UUID.randomUUID().toString()
            : acknowledgementId;
        this.payload = payload;
    }

    @Override
    public String getAcknowledgementId() {
        return acknowledgementId;
    }

    @Override
    public AcknowledgementEventPayload getPayload() {
        return payload;
    }

    public void setAcknowledgementId(String acknowledgementId) {
        this.acknowledgementId = acknowledgementId;
    }
    public void setPayload(AcknowledgementEventPayload payload) {
        this.payload = payload;
    }
}
