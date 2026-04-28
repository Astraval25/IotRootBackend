package com.astraval.iotrootbackend.modules.device;

import com.astraval.iotrootbackend.modules.device.dto.DeviceConnectionStatusResponse;
import com.astraval.iotrootbackend.modules.usage.DeviceUsageService;
import com.astraval.iotrootbackend.modules.usage.dto.DeviceUsageSummaryResponse;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DeviceStatusStreamScheduler {

    private final DeviceStatusPushService pushService;
    private final DeviceService deviceService;
    private final DeviceUsageService deviceUsageService;

    public DeviceStatusStreamScheduler(DeviceStatusPushService pushService, DeviceService deviceService,
                                       DeviceUsageService deviceUsageService) {
        this.pushService = pushService;
        this.deviceService = deviceService;
        this.deviceUsageService = deviceUsageService;
    }

    @Scheduled(fixedDelayString = "${vernemq.stream.fixed-delay-ms:8000}")
    public void streamLiveStatuses() {
        for (Long userId : pushService.getConnectedUserIds()) {
            List<DeviceConnectionStatusResponse> statuses = deviceService.getDeviceConnectionStatusesByUserId(userId);
            pushService.pushStatuses(userId, statuses, true);

            DeviceUsageSummaryResponse usageSummary = deviceUsageService.getUsageSummaryForUser(userId, null, null);
            pushService.pushUsageOverview(userId, usageSummary, true);
        }
    }
}
