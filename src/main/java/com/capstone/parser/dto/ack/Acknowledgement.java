package com.capstone.parser.dto.ack;

public interface Acknowledgement<T> {
    String getAcknowledgementId();
    T getPayload();
}
