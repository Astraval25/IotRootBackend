package com.astraval.iotrootbackend.modules.device;

import com.astraval.iotrootbackend.modules.device.dto.DeviceConnectionStatusResponse;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DeviceStatusStreamScheduler {

    private final DeviceStatusPushService pushService;
    private final DeviceService deviceService;

    public DeviceStatusStreamScheduler(DeviceStatusPushService pushService, DeviceService deviceService) {
        this.pushService = pushService;
        this.deviceService = deviceService;
    }

    @Scheduled(fixedDelayString = "${vernemq.stream.fixed-delay-ms:8000}")
    public void streamLiveStatuses() {
        for (Long userId : pushService.getConnectedUserIds()) {
            List<DeviceConnectionStatusResponse> statuses = deviceService.getDeviceConnectionStatusesByUserId(userId);
            pushService.pushStatuses(userId, statuses, true);
        }
    }
}
