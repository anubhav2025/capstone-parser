package com.capstone.parser.service;

import java.util.List;

/**
 * Simple utility to hold the changed (new or updated) finding IDs
 * while processing. This is one approach (ThreadLocal).
 * Alternatively, you can return these IDs from your process method.
 */
public class ParserContextHolder {
    private static final ThreadLocal<List<String>> changedIds = new ThreadLocal<>();

    public static void setChangedFindingIds(List<String> ids) {
        changedIds.set(ids);
    }

    public static List<String> getChangedFindingIds() {
        return changedIds.get();
    }

    public static void clear() {
        changedIds.remove();
    }
}
