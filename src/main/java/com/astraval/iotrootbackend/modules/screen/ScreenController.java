package com.astraval.iotrootbackend.modules.screen;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.common.util.SecurityUtil;
import com.astraval.iotrootbackend.modules.screen.dto.ScreenRequest;
import com.astraval.iotrootbackend.modules.screen.dto.ScreenResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/screens")
public class ScreenController {

    private final ScreenService screenService;
    private final SecurityUtil securityUtil;

    public ScreenController(ScreenService screenService, SecurityUtil securityUtil) {
        this.screenService = screenService;
        this.securityUtil = securityUtil;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<ScreenResponse>>> getAll() {
        List<ScreenResponse> data = screenService.getScreens(securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Screens fetched"));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ScreenResponse>> getOne(@PathVariable Long id) {
        ScreenResponse data = screenService.getScreen(id, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.ok(data, "Screen fetched"));
    }

    @PostMapping
    public ResponseEntity<ApiResponse<ScreenResponse>> create(@Valid @RequestBody ScreenRequest req) {
        ScreenResponse data = screenService.createScreen(req, securityUtil.getCurrentSub());
        return ResponseEntity.status(201).body(ApiResponseFactory.created(data, "Screen created"));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<ScreenResponse>> update(@PathVariable Long id,
                                                               @Valid @RequestBody ScreenRequest req) {
        ScreenResponse data = screenService.updateScreen(id, req, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.updated(data, "Screen updated"));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long id) {
        screenService.deleteScreen(id, securityUtil.getCurrentSub());
        return ResponseEntity.ok(ApiResponseFactory.deleted("Screen deleted"));
    }
}

