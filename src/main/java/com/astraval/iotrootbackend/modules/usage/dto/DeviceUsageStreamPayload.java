package com.astraval.iotrootbackend.modules.usage.dto;

import lombok.Data;

import java.util.List;

@Data
public class DeviceUsageStreamPayload {
    private Long deviceId;
    private String clientId;
    private DeviceUsageSummaryResponse deviceSummary;
    private DeviceUsageSummaryResponse accountSummary;
    private List<DeviceUsageBucketResponse> recentBuckets;
}
