package com.astraval.iotrootbackend.modules.schedule;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.common.util.SecurityUtil;
import com.astraval.iotrootbackend.modules.schedule.dto.ScheduleRequest;
import com.astraval.iotrootbackend.modules.schedule.dto.ScheduleResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/schedules")
public class ScheduleController {

    private final ScheduleService scheduleService;
    private final SecurityUtil securityUtil;

    public ScheduleController(ScheduleService scheduleService, SecurityUtil securityUtil) {
        this.scheduleService = scheduleService;
        this.securityUtil = securityUtil;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<ScheduleResponse>>> getAll() {
        List<ScheduleResponse> data = scheduleService.getSchedules(securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Schedules fetched"));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ScheduleResponse>> getOne(@PathVariable Long id) {
        ScheduleResponse data = scheduleService.getSchedule(id, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Schedule fetched"));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<ScheduleResponse>> create(@Valid @RequestBody ScheduleRequest req) {
        ScheduleResponse data = scheduleService.createSchedule(req, securityUtil.getCurrentSub());
        return ResponseEntity.status(201).body(ApiResponseFactory.created(data, "Schedule created"));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<ScheduleResponse>> update(@PathVariable Long id,
                                                                 @Valid @RequestBody ScheduleRequest req) {
        ScheduleResponse data = scheduleService.updateSchedule(id, req, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.updated(data, "Schedule updated"));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long id) {
        scheduleService.deleteSchedule(id, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.deleted("Schedule deleted"));
    }
}

