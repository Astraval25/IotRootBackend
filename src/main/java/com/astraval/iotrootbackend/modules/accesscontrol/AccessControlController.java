package com.astraval.iotrootbackend.modules.accesscontrol;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.common.util.SecurityUtil;
import com.astraval.iotrootbackend.modules.accesscontrol.dto.AccessControlRequest;
import com.astraval.iotrootbackend.modules.accesscontrol.dto.AccessControlResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/devices/{deviceId}/rules")
public class AccessControlController {

    private final AccessControlService accessControlService;
    private final SecurityUtil securityUtil;

    public AccessControlController(AccessControlService accessControlService, SecurityUtil securityUtil) {
        this.accessControlService = accessControlService;
        this.securityUtil = securityUtil;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<AccessControlResponse>>> getAll(@PathVariable Long deviceId) {
        List<AccessControlResponse> data = accessControlService.getRules(deviceId, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Rules fetched"));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<AccessControlResponse>> add(@PathVariable Long deviceId,
                                                                   @Valid @RequestBody AccessControlRequest req) {
        AccessControlResponse data = accessControlService.addRule(deviceId, req, securityUtil.getCurrentSub());
        return ResponseEntity.status(201).body(ApiResponseFactory.created(data, "Rule added"));
    }

    @PutMapping("/{ruleId}")
    public ResponseEntity<ApiResponse<AccessControlResponse>> update(@PathVariable Long deviceId,
                                                                      @PathVariable Long ruleId,
                                                                      @Valid @RequestBody AccessControlRequest req) {
        AccessControlResponse data = accessControlService.updateRule(deviceId, ruleId, req, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.updated(data, "Rule updated"));
    }

    @DeleteMapping("/{ruleId}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long deviceId, @PathVariable Long ruleId) {
        accessControlService.deleteRule(deviceId, ruleId, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.deleted("Rule deleted"));
    }
}
