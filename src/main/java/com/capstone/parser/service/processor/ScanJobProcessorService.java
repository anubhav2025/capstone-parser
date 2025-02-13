package com.capstone.parser.service.processor;

public interface ScanJobProcessorService {
    /**
     * Process the scan results from the provided JSON file path,
     * saving them into the given ES index.
     */
    void processJob(String filePath, String esIndex) throws Exception;
}
