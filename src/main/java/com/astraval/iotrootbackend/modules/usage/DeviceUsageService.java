package com.astraval.iotrootbackend.modules.usage;

import com.astraval.iotrootbackend.common.exception.BadRequestException;
import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.device.DeviceRepository;
import com.astraval.iotrootbackend.modules.usage.dto.DeviceUsageBucketResponse;
import com.astraval.iotrootbackend.modules.usage.dto.DeviceUsageSummaryResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

@Service
public class DeviceUsageService {

    private final DeviceRepository deviceRepository;
    private final DeviceUsageBucketRepository bucketRepository;

    public DeviceUsageService(DeviceRepository deviceRepository, DeviceUsageBucketRepository bucketRepository) {
        this.deviceRepository = deviceRepository;
        this.bucketRepository = bucketRepository;
    }

    @Transactional
    public void ingestWebhookEvent(Map<String, Object> payload, String hookName) {
        String clientId = firstNonBlank(
                toText(payload.get("client_id")),
                toText(payload.get("clientId"))
        );
        if (clientId == null) {
            return;
        }

        Device device = deviceRepository.findByClientId(clientId).orElse(null);
        if (device == null) {
            return;
        }

        String topic = firstNonBlank(toText(payload.get("topic")), "unknown/topic");
        UsageDirection direction = detectDirection(payload, hookName);
        long payloadBytes = detectPayloadBytes(payload);
        long estimatedTotal = estimateTotalBytes(topic, payloadBytes);
        Instant bucketStart = Instant.now().truncatedTo(ChronoUnit.HOURS);

        DeviceUsageBucket bucket = bucketRepository
                .findByDeviceIdAndTopicAndDirectionAndBucketStart(device.getId(), topic, direction, bucketStart)
                .orElseGet(() -> {
                    DeviceUsageBucket next = new DeviceUsageBucket();
                    next.setDevice(device);
                    next.setClientId(device.getClientId());
                    next.setTopic(topic);
                    next.setDirection(direction);
                    next.setBucketStart(bucketStart);
                    next.setMessageCount(0L);
                    next.setPayloadBytes(0L);
                    next.setEstimatedTotalBytes(0L);
                    return next;
                });

        bucket.setMessageCount(bucket.getMessageCount() + 1);
        bucket.setPayloadBytes(bucket.getPayloadBytes() + payloadBytes);
        bucket.setEstimatedTotalBytes(bucket.getEstimatedTotalBytes() + estimatedTotal);
        bucketRepository.save(bucket);
    }

    @Transactional(readOnly = true)
    public DeviceUsageSummaryResponse getUsageSummaryForDevice(Long deviceId, Long userId, Instant from, Instant to) {
        Device device = deviceRepository.findByIdAndUserUserId(deviceId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Device not found"));
        Instant fromValue = from != null ? from : Instant.now().minus(24, ChronoUnit.HOURS);
        Instant toValue = to != null ? to : Instant.now();
        validateRange(fromValue, toValue);

        List<DeviceUsageBucket> buckets = bucketRepository.findByDeviceAndRange(device.getId(), fromValue, toValue);
        return summarize(device.getId(), device.getClientId(), buckets, fromValue, toValue);
    }

    @Transactional(readOnly = true)
    public DeviceUsageSummaryResponse getUsageSummaryForUser(Long userId, Instant from, Instant to) {
        Instant fromValue = from != null ? from : Instant.now().minus(24, ChronoUnit.HOURS);
        Instant toValue = to != null ? to : Instant.now();
        validateRange(fromValue, toValue);

        List<DeviceUsageBucket> buckets = bucketRepository.findByUserAndRange(userId, fromValue, toValue);
        return summarize(null, "all", buckets, fromValue, toValue);
    }

    @Transactional(readOnly = true)
    public List<DeviceUsageBucketResponse> getUsageBucketsForDevice(Long deviceId, Long userId, Instant from, Instant to) {
        Device device = deviceRepository.findByIdAndUserUserId(deviceId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Device not found"));
        Instant fromValue = from != null ? from : Instant.now().minus(24, ChronoUnit.HOURS);
        Instant toValue = to != null ? to : Instant.now();
        validateRange(fromValue, toValue);

        return bucketRepository.findByDeviceAndRange(device.getId(), fromValue, toValue)
                .stream().map(DeviceUsageBucketResponse::from).toList();
    }

    private DeviceUsageSummaryResponse summarize(Long deviceId, String clientId, List<DeviceUsageBucket> buckets,
                                                 Instant from, Instant to) {
        long inMsg = 0;
        long outMsg = 0;
        long inPayload = 0;
        long outPayload = 0;
        long inTotal = 0;
        long outTotal = 0;

        for (DeviceUsageBucket bucket : buckets) {
            if (bucket.getDirection() == UsageDirection.INBOUND) {
                inMsg += bucket.getMessageCount();
                inPayload += bucket.getPayloadBytes();
                inTotal += bucket.getEstimatedTotalBytes();
            } else {
                outMsg += bucket.getMessageCount();
                outPayload += bucket.getPayloadBytes();
                outTotal += bucket.getEstimatedTotalBytes();
            }
        }

        DeviceUsageSummaryResponse response = new DeviceUsageSummaryResponse();
        response.setDeviceId(deviceId);
        response.setClientId(clientId);
        response.setInboundMessages(inMsg);
        response.setOutboundMessages(outMsg);
        response.setInboundPayloadBytes(inPayload);
        response.setOutboundPayloadBytes(outPayload);
        response.setInboundEstimatedTotalBytes(inTotal);
        response.setOutboundEstimatedTotalBytes(outTotal);
        response.setFrom(from);
        response.setTo(to);
        return response;
    }

    private UsageDirection detectDirection(Map<String, Object> payload, String hookName) {
        String headerHook = hookName == null ? null : hookName.trim().toLowerCase();
        if (headerHook != null && headerHook.contains("deliver")) {
            return UsageDirection.OUTBOUND;
        }
        if (headerHook != null && headerHook.contains("publish")) {
            return UsageDirection.INBOUND;
        }

        String direction = toText(payload.get("direction"));
        String hook = firstNonBlank(toText(payload.get("event")), toText(payload.get("hook")));
        if (direction != null) {
            String normalized = direction.trim().toLowerCase();
            if (normalized.startsWith("out")) {
                return UsageDirection.OUTBOUND;
            }
            if (normalized.startsWith("in")) {
                return UsageDirection.INBOUND;
            }
        }
        if (hook != null && hook.toLowerCase().contains("deliver")) {
            return UsageDirection.OUTBOUND;
        }
        return UsageDirection.INBOUND;
    }

    private long detectPayloadBytes(Map<String, Object> payload) {
        Long payloadSize = toLong(payload.get("payload_size"));
        if (payloadSize != null && payloadSize >= 0) {
            return payloadSize;
        }

        String data = toText(payload.get("payload"));
        if (data != null) {
            return data.getBytes(StandardCharsets.UTF_8).length;
        }
        return 0;
    }

    private long estimateTotalBytes(String topic, long payloadBytes) {
        int topicBytes = topic.getBytes(StandardCharsets.UTF_8).length;
        int mqttOverheadEstimate = 14;
        return payloadBytes + topicBytes + mqttOverheadEstimate;
    }

    private void validateRange(Instant from, Instant to) {
        if (from.isAfter(to)) {
            throw new BadRequestException("Invalid range: from must be before to");
        }
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private String toText(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private Long toLong(Object value) {
        if (value == null) {
            return null;
        }
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException exception) {
            return null;
        }
    }
}
