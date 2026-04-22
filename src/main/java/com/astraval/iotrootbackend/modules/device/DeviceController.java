package com.astraval.iotrootbackend.modules.device;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.common.util.SecurityUtil;
import com.astraval.iotrootbackend.modules.device.dto.DeviceRequest;
import com.astraval.iotrootbackend.modules.device.dto.DeviceResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final DeviceService deviceService;
    private final SecurityUtil securityUtil;

    public DeviceController(DeviceService deviceService, SecurityUtil securityUtil) {
        this.deviceService = deviceService;
        this.securityUtil = securityUtil;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<DeviceResponse>>> getAll() {
        List<DeviceResponse> data = deviceService.getDevices(securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Devices fetched"));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<DeviceResponse>> getOne(@PathVariable Long id) {
        DeviceResponse data = deviceService.getDevice(id, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Device fetched"));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<DeviceResponse>> create(@Valid @RequestBody DeviceRequest req) {
        DeviceResponse data = deviceService.createDevice(req, securityUtil.getCurrentSub());
        return ResponseEntity.status(201).body(ApiResponseFactory.created(data, "Device created"));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<DeviceResponse>> update(@PathVariable Long id,
                                                               @Valid @RequestBody DeviceRequest req) {
        DeviceResponse data = deviceService.updateDevice(id, req, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.updated(data, "Device updated"));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long id) {
        deviceService.deleteDevice(id, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.deleted("Device deleted"));
    }
}
