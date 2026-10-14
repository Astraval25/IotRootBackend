package com.astraval.iotrootbackend.modules.storeddata;

import com.astraval.iotrootbackend.common.exception.BadRequestException;
import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.storeddata.dto.StoredMessagePageResponse;
import com.astraval.iotrootbackend.modules.storeddata.dto.StoredMessageResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class StoredMessageService {

    private static final Duration MAX_QUERY_RANGE = Duration.ofDays(31);
    private static final int MAX_PAYLOAD_BYTES = 1_048_576;

    private final StoredMessageRepository repository;
    private final ObjectMapper objectMapper;

    public StoredMessageService(StoredMessageRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void storePublishedMessageIfApplicable(Map<String, Object> event, String hookName, Device device) {
        if (!isPublishHook(event, hookName)) {
            return;
        }

        String topic = text(event.get("topic"));
        StoreTopic storeTopic = parseStoreTopic(topic);
        if (storeTopic == null) {
            return;
        }

        Long actualUserId = device.getUser() == null ? null : device.getUser().getUserId();
        if (actualUserId == null || !actualUserId.equals(storeTopic.userId())) {
            log.warn("Rejected stored MQTT message for client {} because topic user {} does not match device owner",
                    device.getClientId(), storeTopic.userId());
            return;
        }

        Object rawPayload = event.get("payload");
        JsonNode json = parseJson(rawPayload, device.getClientId(), topic);
        if (json == null) {
            return;
        }

        int payloadBytes = payloadBytes(rawPayload, json);
        if (payloadBytes > MAX_PAYLOAD_BYTES) {
            log.warn("Rejected stored MQTT payload larger than {} bytes for client {}", MAX_PAYLOAD_BYTES,
                    device.getClientId());
            return;
        }

        StoredMessage message = new StoredMessage();
        message.setUser(device.getUser());
        message.setDevice(device);
        message.setClientId(device.getClientId());
        message.setTopic(topic);
        message.setStorePath(storeTopic.path());
        message.setPayload(json);
        message.setPayloadBytes((long) payloadBytes);
        message.setQos(integer(event.get("qos")));
        message.setRetained(booleanValue(event.get("retain"), event.get("retained")));
        message.setReceivedAt(Instant.now());
        repository.save(message);
    }

    @Transactional(readOnly = true)
    public StoredMessagePageResponse query(Long userId, Instant from, Instant to, Long deviceId,
                                           String topic, String topicPrefix, int page, int size) {
        Instant toValue = to != null ? to : Instant.now();
        Instant fromValue = from != null ? from : toValue.minus(1, ChronoUnit.HOURS);
        if (fromValue.isAfter(toValue)) {
            throw new BadRequestException("Invalid range: from must be before to");
        }
        if (Duration.between(fromValue, toValue).compareTo(MAX_QUERY_RANGE) > 0) {
            throw new BadRequestException("Query range cannot exceed 31 days");
        }

        String normalizedTopic = topic == null || topic.isBlank() ? null : topic.trim();
        String normalizedPrefix = topicPrefix == null || topicPrefix.isBlank() ? null : topicPrefix.trim();
        Specification<StoredMessage> filters = (root, query, criteriaBuilder) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new java.util.ArrayList<>();
            predicates.add(criteriaBuilder.equal(root.get("user").get("userId"), userId));
            predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("receivedAt"), fromValue));
            predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("receivedAt"), toValue));
            if (deviceId != null) {
                predicates.add(criteriaBuilder.equal(root.get("device").get("id"), deviceId));
            }
            if (normalizedTopic != null) {
                predicates.add(criteriaBuilder.equal(root.get("topic"), normalizedTopic));
            }
            if (normalizedPrefix != null) {
                predicates.add(criteriaBuilder.like(root.get("topic"), escapeLike(normalizedPrefix) + "%", '\\'));
            }
            return criteriaBuilder.and(predicates.toArray(jakarta.persistence.criteria.Predicate[]::new));
        };
        PageRequest pageRequest = PageRequest.of(page, size,
                Sort.by(Sort.Order.desc("receivedAt"), Sort.Order.desc("id")));
        Page<StoredMessage> result = repository.findAll(filters, pageRequest);

        StoredMessagePageResponse response = new StoredMessagePageResponse();
        response.setContent(result.getContent().stream().map(StoredMessageResponse::from).toList());
        response.setPage(result.getNumber());
        response.setSize(result.getSize());
        response.setTotalElements(result.getTotalElements());
        response.setTotalPages(result.getTotalPages());
        response.setFrom(fromValue);
        response.setTo(toValue);
        return response;
    }

    @Transactional
    public void deleteForDevice(Long deviceId) {
        repository.deleteByDeviceId(deviceId);
    }

    private boolean isPublishHook(Map<String, Object> event, String hookName) {
        String hook = firstNonBlank(hookName, text(event.get("event")), text(event.get("hook")));
        return hook != null && hook.toLowerCase().contains("publish");
    }

    private StoreTopic parseStoreTopic(String topic) {
        if (topic == null || topic.length() > 255 || topic.contains("+") || topic.contains("#")) {
            return null;
        }
        String normalized = topic.startsWith("/") ? topic.substring(1) : topic;
        String[] levels = normalized.split("/", -1);
        if (levels.length < 4 || !"iot".equals(levels[0]) || !"store".equals(levels[1])) {
            return null;
        }
        String path = String.join("/", Arrays.copyOfRange(levels, 3, levels.length));
        if (path.isBlank() || path.length() > 255
                || Arrays.stream(Arrays.copyOfRange(levels, 3, levels.length)).anyMatch(String::isBlank)) {
            return null;
        }
        try {
            return new StoreTopic(Long.parseLong(levels[2]), path);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private JsonNode parseJson(Object rawPayload, String clientId, String topic) {
        if (rawPayload == null) {
            log.warn("Rejected empty stored MQTT payload for client {} on topic {}", clientId, topic);
            return null;
        }
        try {
            if (rawPayload instanceof String payloadText) {
                JsonNode parsed = objectMapper.readTree(payloadText);
                return parsed == null ? null : parsed;
            }
            return objectMapper.valueToTree(rawPayload);
        } catch (JsonProcessingException | IllegalArgumentException exception) {
            log.warn("Rejected non-JSON stored MQTT payload for client {} on topic {}", clientId, topic);
            return null;
        }
    }

    private int payloadBytes(Object rawPayload, JsonNode json) {
        String value = rawPayload instanceof String text ? text : json.toString();
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private Integer integer(Object value) {
        if (value == null) return null;
        try {
            return Integer.valueOf(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private Boolean booleanValue(Object... values) {
        for (Object value : values) {
            if (value != null) {
                String normalized = String.valueOf(value).trim();
                return "true".equalsIgnoreCase(normalized) || "1".equals(normalized);
            }
        }
        return false;
    }

    private String firstNonBlank(String... values) {
        return Arrays.stream(values).filter(value -> value != null && !value.isBlank()).findFirst().orElse(null);
    }

    private String escapeLike(String value) {
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private record StoreTopic(Long userId, String path) {
    }
}
