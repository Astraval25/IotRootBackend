package com.astraval.iotrootbackend.modules.device;

import com.astraval.iotrootbackend.modules.device.dto.DeviceConnectionStatusResponse;
import com.astraval.iotrootbackend.modules.usage.DeviceUsageService;
import com.astraval.iotrootbackend.modules.usage.dto.DeviceUsageSummaryResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.List;

@Component
public class DeviceStatusWebSocketHandler extends TextWebSocketHandler {

    private final DeviceStatusPushService pushService;
    private final DeviceService deviceService;
    private final DeviceUsageService deviceUsageService;

    public DeviceStatusWebSocketHandler(DeviceStatusPushService pushService, DeviceService deviceService,
                                        DeviceUsageService deviceUsageService) {
        this.pushService = pushService;
        this.deviceService = deviceService;
        this.deviceUsageService = deviceUsageService;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        Long userId = (Long) session.getAttributes().get("userId");
        if (userId == null) {
            return;
        }

        pushService.register(userId, session);
        List<DeviceConnectionStatusResponse> statuses = deviceService.getDeviceConnectionStatusesByUserId(userId);
        pushService.pushStatuses(userId, statuses, false);
        DeviceUsageSummaryResponse usageSummary = deviceUsageService.getUsageSummaryForUser(userId, null, null);
        pushService.pushUsageOverview(userId, usageSummary, false);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        Long userId = (Long) session.getAttributes().get("userId");
        if (userId == null) {
            return;
        }
        pushService.unregister(userId, session);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        // Client does not need to send messages for this stream.
    }
}
