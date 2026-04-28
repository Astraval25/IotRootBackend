package com.astraval.iotrootbackend.modules.usage.dto;

import com.astraval.iotrootbackend.modules.usage.DeviceUsageBucket;
import lombok.Data;

import java.time.Instant;

@Data
public class DeviceUsageBucketResponse {
    private Instant bucketStart;
    private String topic;
    private String direction;
    private Long messageCount;
    private Long payloadBytes;
    private Long estimatedTotalBytes;

    public static DeviceUsageBucketResponse from(DeviceUsageBucket bucket) {
        DeviceUsageBucketResponse response = new DeviceUsageBucketResponse();
        response.setBucketStart(bucket.getBucketStart());
        response.setTopic(bucket.getTopic());
        response.setDirection(bucket.getDirection().name());
        response.setMessageCount(bucket.getMessageCount());
        response.setPayloadBytes(bucket.getPayloadBytes());
        response.setEstimatedTotalBytes(bucket.getEstimatedTotalBytes());
        return response;
    }
}
