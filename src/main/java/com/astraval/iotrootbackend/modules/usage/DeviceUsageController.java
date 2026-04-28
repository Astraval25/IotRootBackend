package com.astraval.iotrootbackend.modules.usage;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.common.util.SecurityUtil;
import com.astraval.iotrootbackend.common.exception.UnauthorizedException;
import com.astraval.iotrootbackend.modules.usage.dto.DeviceUsageBucketResponse;
import com.astraval.iotrootbackend.modules.usage.dto.DeviceUsageSummaryResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
public class DeviceUsageController {

    private final DeviceUsageService deviceUsageService;
    private final SecurityUtil securityUtil;
    private final String webhookSecret;

    public DeviceUsageController(DeviceUsageService deviceUsageService, SecurityUtil securityUtil,
                                 @Value("${vernemq.webhook.secret:}") String webhookSecret) {
        this.deviceUsageService = deviceUsageService;
        this.securityUtil = securityUtil;
        this.webhookSecret = webhookSecret;
    }

    @PostMapping("/api/vernemq/webhooks/usage")
    public ResponseEntity<ApiResponse<Void>> ingestUsage(
            @RequestBody Map<String, Object> payload,
            @RequestHeader(value = "X-Webhook-Secret", required = false) String incomingSecret
    ) {
        if (webhookSecret != null && !webhookSecret.isBlank() && !webhookSecret.equals(incomingSecret)) {
            throw new UnauthorizedException("Invalid webhook secret");
        }
        deviceUsageService.ingestWebhookEvent(payload);
        return ResponseEntity.ok(ApiResponseFactory.ok(null, "Usage event accepted"));
    }

    @GetMapping("/api/devices/{id}/usage/summary")
    public ResponseEntity<ApiResponse<DeviceUsageSummaryResponse>> getDeviceUsageSummary(
            @PathVariable Long id,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to
    ) {
        Long userId = Long.parseLong(securityUtil.getCurrentSub());
        DeviceUsageSummaryResponse data = deviceUsageService.getUsageSummaryForDevice(id, userId, from, to);
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Device usage summary fetched"));
    }

    @GetMapping("/api/devices/{id}/usage/buckets")
    public ResponseEntity<ApiResponse<List<DeviceUsageBucketResponse>>> getDeviceUsageBuckets(
            @PathVariable Long id,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to
    ) {
        Long userId = Long.parseLong(securityUtil.getCurrentSub());
        List<DeviceUsageBucketResponse> data = deviceUsageService.getUsageBucketsForDevice(id, userId, from, to);
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Device usage buckets fetched"));
    }

    @GetMapping("/api/devices/usage/summary")
    public ResponseEntity<ApiResponse<DeviceUsageSummaryResponse>> getUserUsageSummary(
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to
    ) {
        Long userId = Long.parseLong(securityUtil.getCurrentSub());
        DeviceUsageSummaryResponse data = deviceUsageService.getUsageSummaryForUser(userId, from, to);
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Usage summary fetched"));
    }
}
