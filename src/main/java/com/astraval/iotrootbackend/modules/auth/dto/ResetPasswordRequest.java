package com.astraval.iotrootbackend.modules.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank(message = "Email is required") @Email(message = "Invalid email format") String email,
        @NotBlank(message = "OTP is required") @Pattern(regexp = "\\d{6}", message = "OTP must be a 6-digit number") String otp,
        @NotBlank(message = "New password is required") @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters") String newPassword) {
}
