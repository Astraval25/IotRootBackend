package com.astraval.iotrootbackend.modules.device;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;

@Service
public class DeviceStatusPushService {

    private final ObjectMapper objectMapper;
    private final Map<Long, Set<WebSocketSession>> sessionsByUserId = new ConcurrentHashMap<>();
    private final Map<Long, Map<String, String>> lastPayloadByUserId = new ConcurrentHashMap<>();

    public DeviceStatusPushService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void register(Long userId, WebSocketSession session) {
        sessionsByUserId.computeIfAbsent(userId, ignored -> new CopyOnWriteArraySet<>()).add(session);
    }

    public void unregister(Long userId, WebSocketSession session) {
        Set<WebSocketSession> sessions = sessionsByUserId.get(userId);
        if (sessions == null) {
            return;
        }
        sessions.remove(session);
        if (sessions.isEmpty()) {
            sessionsByUserId.remove(userId);
            lastPayloadByUserId.remove(userId);
        }
    }

    public Set<Long> getConnectedUserIds() {
        return sessionsByUserId.keySet();
    }

    public void pushStatuses(Long userId, List<?> statuses, boolean skipIfSamePayload) {
        pushEvent(userId, "device_status_snapshot", statuses, skipIfSamePayload);
    }

    public void pushUsageOverview(Long userId, Object usageSummary, boolean skipIfSamePayload) {
        pushEvent(userId, "usage_overview_snapshot", usageSummary, skipIfSamePayload);
    }

    public void pushDeviceUsage(Long userId, Object usagePayload, boolean skipIfSamePayload) {
        pushEvent(userId, "device_usage_snapshot", usagePayload, skipIfSamePayload);
    }

    private void pushEvent(Long userId, String eventName, Object data, boolean skipIfSamePayload) {
        Set<WebSocketSession> sessions = sessionsByUserId.get(userId);
        if (sessions == null || sessions.isEmpty()) {
            return;
        }

        try {
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("event", eventName);
            envelope.put("data", data);
            String payload = objectMapper.writeValueAsString(envelope);

            Map<String, String> payloadsByEvent = lastPayloadByUserId.computeIfAbsent(
                    userId,
                    ignored -> new ConcurrentHashMap<>()
            );

            if (skipIfSamePayload && payload.equals(payloadsByEvent.get(eventName))) {
                return;
            }

            TextMessage message = new TextMessage(payload);
            for (WebSocketSession session : sessions) {
                if (!session.isOpen()) {
                    unregister(userId, session);
                    continue;
                }
                session.sendMessage(message);
            }
            payloadsByEvent.put(eventName, payload);
        } catch (JsonProcessingException ignored) {
            // Ignore malformed serialization edge cases; REST remains fallback.
        } catch (IOException ignored) {
            // Ignore individual socket write failures.
        }
    }
}
