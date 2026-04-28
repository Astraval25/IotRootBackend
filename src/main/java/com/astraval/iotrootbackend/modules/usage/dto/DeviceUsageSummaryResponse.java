package com.astraval.iotrootbackend.modules.usage.dto;

import lombok.Data;

import java.time.Instant;

@Data
public class DeviceUsageSummaryResponse {
    private Long deviceId;
    private String clientId;
    private Long inboundMessages;
    private Long outboundMessages;
    private Long inboundPayloadBytes;
    private Long outboundPayloadBytes;
    private Long inboundEstimatedTotalBytes;
    private Long outboundEstimatedTotalBytes;
    private Instant from;
    private Instant to;
}
