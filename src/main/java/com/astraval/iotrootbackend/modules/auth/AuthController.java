package com.astraval.iotrootbackend.modules.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.astraval.iotrootbackend.common.util.ApiResponse;
import com.astraval.iotrootbackend.common.util.ApiResponseFactory;
import com.astraval.iotrootbackend.modules.auth.dto.AuthTokenResponse;
import com.astraval.iotrootbackend.modules.auth.dto.ForgotPasswordRequest;
import com.astraval.iotrootbackend.modules.auth.dto.LoginRequest;
import com.astraval.iotrootbackend.modules.auth.dto.RegisterRequest;
import com.astraval.iotrootbackend.modules.auth.dto.RegisterResponse;
import com.astraval.iotrootbackend.modules.auth.dto.ResetPasswordRequest;
import com.astraval.iotrootbackend.modules.auth.dto.TokenRefreshRequest;
import com.astraval.iotrootbackend.modules.auth.dto.VerifyOtpRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(@Valid @RequestBody RegisterRequest request) {
        RegisterResponse response = authService.register(request);
        return ResponseEntity.status(201)
                .body(ApiResponseFactory.created(response, "User registered successfully. Verify OTP to activate account."));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse<Void>> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        authService.verifyOtp(request);
        return ResponseEntity.ok(ApiResponseFactory.ok(null, "Account verified successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthTokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        AuthTokenResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponseFactory.ok(response, "Login successful"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<AuthTokenResponse>> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        AuthTokenResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(ApiResponseFactory.ok(response, "Token refreshed successfully"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.forgotPassword(request);
        return ResponseEntity.ok(ApiResponseFactory.ok(null, "If the account exists, OTP has been sent"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(ApiResponseFactory.ok(null, "Password reset successful"));
    }
}
