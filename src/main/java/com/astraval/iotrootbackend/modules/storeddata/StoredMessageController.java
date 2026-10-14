package com.astraval.iotrootbackend.modules.storeddata;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.common.util.SecurityUtil;
import com.astraval.iotrootbackend.modules.storeddata.dto.StoredMessagePageResponse;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@Validated
@RestController
@RequestMapping("/api/store/messages")
public class StoredMessageController {

    private final StoredMessageService service;
    private final SecurityUtil securityUtil;

    public StoredMessageController(StoredMessageService service, SecurityUtil securityUtil) {
        this.service = service;
        this.securityUtil = securityUtil;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<StoredMessagePageResponse>> getMessages(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) Long deviceId,
            @RequestParam(required = false) String topic,
            @RequestParam(required = false) String topicPrefix,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "50") @Min(1) @Max(200) int size) {
        Long userId = Long.parseLong(securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(
                service.query(userId, from, to, deviceId, topic, topicPrefix, page, size),
                "Stored messages fetched"));
    }
}
