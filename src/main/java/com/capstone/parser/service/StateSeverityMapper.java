package com.capstone.parser.service;

import java.util.Locale;

import com.capstone.parser.model.FindingSeverity;
import com.capstone.parser.model.FindingState;

public class StateSeverityMapper {

    /**
     * Map GH's "open"/"dismissed"/"resolved"/"fixed" etc. to our internal states.
     * You can refine logic based on tool type, dismissed reasons, etc.
     */
    public static FindingState mapGitHubState(String ghState, String dismissedReason) {
        if (ghState == null) {
            return FindingState.OPEN; // default
        }
        String stateLower = ghState.toLowerCase(Locale.ROOT);

        switch (stateLower) {
            case "open":
                return FindingState.OPEN;
            case "resolved":
            case "fixed":
            case "closed":
                return FindingState.FIXED;
            case "dismissed":
                // If there's a reason like "false positive," map to that
                if (dismissedReason != null && dismissedReason.toLowerCase().contains("false")) {
                    return FindingState.FALSE_POSITIVE;
                }
                return FindingState.SUPPRESSED;
            default:
                // fallback
                return FindingState.OPEN;
        }
    }

    /**
     * Example severity mapping from GH or typical severity strings to our internal severities.
     * We handle code-scan's "critical" / "error" / "warning" etc., 
     * or dependabot "critical" / "high" / "moderate" / "low".
     */
    public static FindingSeverity mapGitHubSeverity(String ghSeverity) {
        if (ghSeverity == null) {
            // For secret scanning or unknown, default to HIGH, for example
            return FindingSeverity.HIGH; 
        }
        String sevLower = ghSeverity.toLowerCase(Locale.ROOT);

        // Some possible GH severity values: "critical", "high", "medium"/"moderate", "low", "warning", "error", ...
        switch (sevLower) {
            case "critical":
                return FindingSeverity.CRITICAL;
            case "high":
            case "error":       // code-scan might mark "error" => high
                return FindingSeverity.HIGH;
            case "medium":
            case "moderate":
            case "warning":
                return FindingSeverity.MEDIUM;
            case "low":
            case "note":
                return FindingSeverity.LOW;
            default:
                return FindingSeverity.INFO;
        }
    }

}
