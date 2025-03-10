package com.capstone.parser.dto.event.payload;

import java.util.List;

public class RunbookJobEventPayload {
    private String tenantId;
    private List<String> findingIds;

    public RunbookJobEventPayload() {}

    public RunbookJobEventPayload(String tenantId, List<String> findingIds) {
        this.tenantId = tenantId;
        this.findingIds = findingIds;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public List<String> getFindingIds() {
        return findingIds;
    }

    public void setFindingIds(List<String> findingIds) {
        this.findingIds = findingIds;
    }
}

