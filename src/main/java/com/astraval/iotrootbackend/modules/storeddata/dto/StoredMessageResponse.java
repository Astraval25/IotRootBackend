package com.astraval.iotrootbackend.modules.storeddata.dto;

import com.astraval.iotrootbackend.modules.storeddata.StoredMessage;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
public class StoredMessageResponse {
    private Long id;
    private Long deviceId;
    private String clientId;
    private String topic;
    private String storePath;
    private Object payload;
    private Long payloadBytes;
    private Integer qos;
    private Boolean retained;
    private Instant receivedAt;

    public static StoredMessageResponse from(StoredMessage message) {
        StoredMessageResponse response = new StoredMessageResponse();
        response.setId(message.getId());
        response.setDeviceId(message.getDevice().getId());
        response.setClientId(message.getClientId());
        response.setTopic(message.getTopic());
        response.setStorePath(message.getStorePath());
        response.setPayload(toPlainValue(message.getPayload()));
        response.setPayloadBytes(message.getPayloadBytes());
        response.setQos(message.getQos());
        response.setRetained(message.getRetained());
        response.setReceivedAt(message.getReceivedAt());
        return response;
    }

    /**
     * Convert the Jackson 2 tree used by Hibernate into ordinary Java values.
     * Spring Boot 4's HTTP converter can then serialize the payload as JSON data
     * instead of treating JsonNode itself as a bean and exposing its metadata.
     */
    private static Object toPlainValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            Map<String, Object> value = new LinkedHashMap<>();
            node.fields().forEachRemaining(entry ->
                    value.put(entry.getKey(), toPlainValue(entry.getValue())));
            return value;
        }
        if (node.isArray()) {
            List<Object> value = new ArrayList<>();
            node.forEach(child -> value.add(toPlainValue(child)));
            return value;
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isIntegralNumber()) {
            return node.canConvertToLong() ? node.longValue() : node.bigIntegerValue();
        }
        if (node.isFloatingPointNumber()) {
            return node.decimalValue();
        }
        return node.toString();
    }
}
