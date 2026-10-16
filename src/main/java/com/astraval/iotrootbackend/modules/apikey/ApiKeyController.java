package com.astraval.iotrootbackend.modules.apikey;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.common.util.SecurityUtil;
import com.astraval.iotrootbackend.modules.apikey.dto.ApiKeyCreateRequest;
import com.astraval.iotrootbackend.modules.apikey.dto.ApiKeyCreatedResponse;
import com.astraval.iotrootbackend.modules.apikey.dto.ApiKeyResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/api-keys")
public class ApiKeyController {

    private final ApiKeyService service;
    private final SecurityUtil securityUtil;

    public ApiKeyController(ApiKeyService service, SecurityUtil securityUtil) {
        this.service = service;
        this.securityUtil = securityUtil;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<ApiKeyResponse>>> list() {
        return ResponseEntity.ok(ApiResponseFactory.ok(service.list(userId()), "API keys fetched"));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<ApiKeyCreatedResponse>> create(@Valid @RequestBody ApiKeyCreateRequest request) {
        return ResponseEntity.status(201).body(ApiResponseFactory.created(
                service.create(userId(), request.name()), "API key created"));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> revoke(@PathVariable Long id) {
        service.revoke(userId(), id);
        return ResponseEntity.ok(ApiResponseFactory.deleted("API key deleted"));
    }

    private Long userId() {
        return Long.parseLong(securityUtil.getCurrentSub());
    }
}
