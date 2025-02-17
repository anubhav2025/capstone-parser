package com.capstone.parser.dto.ack.payload;

import com.capstone.parser.dto.ack.AcknowledgementStatus;

public class AcknowledgementEventPayload {
    private AcknowledgementStatus status = AcknowledgementStatus.SUCCESS;
    private String jobId;

    public AcknowledgementEventPayload() {}

    public AcknowledgementEventPayload(String jobId) {
        this.jobId = jobId;
    }

    public AcknowledgementStatus getStatus() {
        return status;
    }

    public void setStatus(AcknowledgementStatus status) {
        this.status = status;
    }

    public String getJobId() {
        return jobId;
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }
}
