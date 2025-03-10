package com.capstone.parser.dto.event;

import java.util.UUID;

import com.capstone.parser.dto.event.payload.RunbookJobEventPayload;
import com.capstone.parser.enums.EventTypes;
import com.fasterxml.jackson.annotation.JsonProperty;

public class RunbookJobEvent implements Event<RunbookJobEventPayload> {

    private EventTypes TYPE = EventTypes.RUNBOOK_JOB;               // Must be from EventTypes
    private String eventId;
    private RunbookJobEventPayload payload;

    public RunbookJobEvent() {
        // default constructor
    }

    public RunbookJobEvent(RunbookJobEventPayload payload) {
        this.payload = payload;
        this.eventId = UUID.randomUUID().toString();
    }

    @Override
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    public EventTypes getType() {
        return TYPE;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public RunbookJobEventPayload getPayload() {
        return payload;
    }
}

