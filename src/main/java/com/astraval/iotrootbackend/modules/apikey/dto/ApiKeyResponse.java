package com.astraval.iotrootbackend.modules.apikey.dto;

import com.astraval.iotrootbackend.modules.apikey.ApiKey;
import lombok.Data;

import java.time.Instant;

@Data
public class ApiKeyResponse {
    private Long id;
    private String name;
    private String prefix;
    private Instant createdAt;
    private Instant lastUsedAt;
    private Instant revokedAt;
    private long successfulRequests;
    private long failedRequests;

    public static ApiKeyResponse from(ApiKey key) {
        ApiKeyResponse response = new ApiKeyResponse();
        response.setId(key.getId());
        response.setName(key.getName());
        response.setPrefix(key.getKeyPrefix());
        response.setCreatedAt(key.getCreatedAt());
        response.setLastUsedAt(key.getLastUsedAt());
        response.setRevokedAt(key.getRevokedAt());
        response.setSuccessfulRequests(key.getSuccessfulRequests());
        response.setFailedRequests(key.getFailedRequests());
        return response;
    }
}
