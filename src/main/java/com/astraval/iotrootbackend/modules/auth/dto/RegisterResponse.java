package com.astraval.iotrootbackend.modules.auth.dto;

import java.time.LocalDateTime;

public record RegisterResponse(
        Long userId,
        String email,
        LocalDateTime otpExpiresAt,
        boolean otpEmailSent) {
}
