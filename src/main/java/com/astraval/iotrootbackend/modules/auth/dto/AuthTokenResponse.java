package com.astraval.iotrootbackend.modules.auth.dto;

public record AuthTokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresInSeconds,
        long refreshExpiresInSeconds) {
}
