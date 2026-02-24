package com.astraval.iotrootbackend.modules.auth;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.astraval.iotrootbackend.common.exception.BadRequestException;
import com.astraval.iotrootbackend.common.exception.UnauthorizedException;
import com.astraval.iotrootbackend.common.util.JwtUtil;
import com.astraval.iotrootbackend.modules.auth.dto.AuthTokenResponse;
import com.astraval.iotrootbackend.modules.auth.dto.ForgotPasswordRequest;
import com.astraval.iotrootbackend.modules.auth.dto.LoginRequest;
import com.astraval.iotrootbackend.modules.auth.dto.RegisterRequest;
import com.astraval.iotrootbackend.modules.auth.dto.RegisterResponse;
import com.astraval.iotrootbackend.modules.auth.dto.ResetPasswordRequest;
import com.astraval.iotrootbackend.modules.auth.dto.TokenRefreshRequest;
import com.astraval.iotrootbackend.modules.auth.dto.VerifyOtpRequest;
import com.astraval.iotrootbackend.modules.auth.otp.OtpPurpose;
import com.astraval.iotrootbackend.modules.auth.otp.UserOtp;
import com.astraval.iotrootbackend.modules.auth.otp.UserOtpRepository;
import com.astraval.iotrootbackend.modules.emailtemplate.EmailTemplateService;
import com.astraval.iotrootbackend.modules.user.User;
import com.astraval.iotrootbackend.modules.user.UserRepository;

import io.jsonwebtoken.Claims;

@Service
public class AuthService {

    private static final SecureRandom OTP_RANDOM = new SecureRandom();
    private static final String OTP_VERIFICATION_TEMPLATE = "OTP Verification";
    private static final String OTP_PASSWORD_RESET_TEMPLATE = "Password Reset OTP";

    private final UserRepository userRepository;
    private final UserOtpRepository userOtpRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailTemplateService emailTemplateService;

    @Value("${auth.otp.expiration-minutes:10}")
    private int otpExpirationMinutes;

    public AuthService(
            UserRepository userRepository,
            UserOtpRepository userOtpRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            EmailTemplateService emailTemplateService) {
        this.userRepository = userRepository;
        this.userOtpRepository = userOtpRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.emailTemplateService = emailTemplateService;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());
        User user = userRepository.findByEmailIgnoreCase(email)
                .map(existingUser -> {
                    if (existingUser.isVerified()) {
                        throw new BadRequestException("User is already registered and verified");
                    }
                    return existingUser;
                })
                .orElseGet(User::new);

        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setVerified(false);
        user.setIsActive(true);
        user = userRepository.save(user);

        OtpDispatchResult otpDispatch = issueOtpForUser(
                user,
                OtpPurpose.REGISTRATION_VERIFICATION,
                OTP_VERIFICATION_TEMPLATE);

        return new RegisterResponse(user.getUserId(), user.getEmail(), otpDispatch.expiresAt(), otpDispatch.emailSent());
    }

    @Transactional
    public void verifyOtp(VerifyOtpRequest request) {
        User user = getActiveUserByEmail(normalizeEmail(request.email()), "Invalid email");

        UserOtp userOtp = validateOtp(user, request.otp(), OtpPurpose.REGISTRATION_VERIFICATION);
        userOtp.setUsed(true);
        userOtpRepository.save(userOtp);

        user.setVerified(true);
        userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public AuthTokenResponse login(LoginRequest request) {
        User user = getActiveUserByEmail(normalizeEmail(request.email()), "Invalid email or password");

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new UnauthorizedException("Invalid email or password");
        }

        if (!user.isVerified()) {
            throw new UnauthorizedException("Account is not verified. Verify OTP first.");
        }

        return buildAuthTokens(user);
    }

    @Transactional(readOnly = true)
    public AuthTokenResponse refreshToken(TokenRefreshRequest request) {
        String refreshToken = request.refreshToken().trim();
        if (!jwtUtil.isTokenValid(refreshToken)) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        Claims claims = jwtUtil.parseClaims(refreshToken);
        String tokenType = claims.get("type", String.class);
        if (!"refresh".equals(tokenType)) {
            throw new UnauthorizedException("Invalid refresh token type");
        }

        Long userId;
        try {
            userId = Long.parseLong(claims.getSubject());
        } catch (NumberFormatException ex) {
            throw new UnauthorizedException("Invalid refresh token subject");
        }

        User user = userRepository.findByUserIdAndIsActiveTrue(userId)
                .orElseThrow(() -> new UnauthorizedException("User not found"));

        if (!user.isVerified()) {
            throw new UnauthorizedException("Account is not verified");
        }

        return buildAuthTokens(user);
    }

    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        String email = normalizeEmail(request.email());
        Optional<User> userOptional = userRepository.findByEmailIgnoreCaseAndIsActiveTrue(email);

        if (userOptional.isEmpty() || !userOptional.get().isVerified()) {
            return;
        }

        issueOtpForUser(
                userOptional.get(),
                OtpPurpose.PASSWORD_RESET,
                OTP_PASSWORD_RESET_TEMPLATE);
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        User user = getActiveUserByEmail(normalizeEmail(request.email()), "Invalid email");
        if (!user.isVerified()) {
            throw new UnauthorizedException("Account is not verified");
        }

        UserOtp userOtp = validateOtp(user, request.otp(), OtpPurpose.PASSWORD_RESET);
        userOtp.setUsed(true);
        userOtpRepository.save(userOtp);

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
    }

    private OtpDispatchResult issueOtpForUser(User user, OtpPurpose purpose, String templateName) {
        userOtpRepository.markAllUnusedAsUsed(user.getUserId(), purpose);

        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(otpExpirationMinutes);
        String otpCode = generateOtpCode();

        UserOtp userOtp = new UserOtp();
        userOtp.setUser(user);
        userOtp.setOtpCode(otpCode);
        userOtp.setPurpose(purpose);
        userOtp.setExpiresAt(expiresAt);
        userOtp.setUsed(false);
        userOtpRepository.save(userOtp);

        boolean otpEmailSent = emailTemplateService.sendTemplatedEmail(
                templateName,
                user.getEmail(),
                Map.of(
                        "otp", otpCode,
                        "otp_expiry_minutes", String.valueOf(otpExpirationMinutes)));
        return new OtpDispatchResult(expiresAt, otpEmailSent);
    }

    private UserOtp validateOtp(User user, String otp, OtpPurpose purpose) {
        UserOtp userOtp = userOtpRepository
                .findTopByUserUserIdAndOtpCodeAndPurposeAndUsedFalseOrderByCreatedDtDesc(user.getUserId(), otp, purpose)
                .orElseThrow(() -> new UnauthorizedException("Invalid OTP"));

        if (userOtp.getExpiresAt().isBefore(LocalDateTime.now())) {
            userOtp.setUsed(true);
            userOtpRepository.save(userOtp);
            throw new UnauthorizedException("OTP has expired");
        }
        return userOtp;
    }

    private AuthTokenResponse buildAuthTokens(User user) {
        String accessToken = jwtUtil.generateToken(user.getUserId(), user.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUserId());
        return new AuthTokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtUtil.getJwtExpirationSeconds(),
                jwtUtil.getRefreshExpirationSeconds());
    }

    private User getActiveUserByEmail(String email, String errorMessage) {
        return userRepository.findByEmailIgnoreCaseAndIsActiveTrue(email)
                .orElseThrow(() -> new UnauthorizedException(errorMessage));
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    private String generateOtpCode() {
        return String.format("%06d", OTP_RANDOM.nextInt(1_000_000));
    }

    private record OtpDispatchResult(LocalDateTime expiresAt, boolean emailSent) {
    }
}
