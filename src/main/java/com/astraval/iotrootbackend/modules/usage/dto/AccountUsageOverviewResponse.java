package com.astraval.iotrootbackend.modules.usage.dto;

import lombok.Data;

import java.time.Instant;

@Data
public class AccountUsageOverviewResponse {
    private Instant from;
    private Instant to;
    private long deviceCount;
    private long inboundMessages;
    private long outboundMessages;
    private long totalTransactions;
    private long inboundPayloadBytes;
    private long outboundPayloadBytes;
    private long inboundEstimatedTotalBytes;
    private long outboundEstimatedTotalBytes;
    private long storedMessageCount;
    private long storedPayloadBytes;
}
