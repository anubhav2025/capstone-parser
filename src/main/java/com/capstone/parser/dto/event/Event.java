package com.capstone.parser.dto.event;

import com.capstone.parser.enums.EventTypes;

public interface Event<T> {
    /**
     * A unique identifier, typically a UUID, for this event.
     */
    String getEventId();

    /**
     * The type of the event (SCAN_REQUEST, PARSE_REQUEST, etc).
     */
    EventTypes getType();

    /**
     * The actual payload object of the event.
     */
    T getPayload();
}
