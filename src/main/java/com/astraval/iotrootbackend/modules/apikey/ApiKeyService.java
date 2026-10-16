package com.astraval.iotrootbackend.modules.apikey;

import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.common.exception.UnauthorizedException;
import com.astraval.iotrootbackend.modules.apikey.dto.ApiKeyCreatedResponse;
import com.astraval.iotrootbackend.modules.apikey.dto.ApiKeyResponse;
import com.astraval.iotrootbackend.modules.user.User;
import com.astraval.iotrootbackend.modules.user.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Service
public class ApiKeyService {

    private static final String KEY_PREFIX = "iotr_live_";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final ApiKeyRepository repository;
    private final UserRepository userRepository;

    public ApiKeyService(ApiKeyRepository repository, UserRepository userRepository) {
        this.repository = repository;
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> list(Long userId) {
        return repository.findByUserUserIdAndRevokedAtIsNullOrderByCreatedAtDesc(userId)
                .stream().map(ApiKeyResponse::from).toList();
    }

    @Transactional
    public ApiKeyCreatedResponse create(Long userId, String name) {
        User user = userRepository.findByUserIdAndIsActiveTrue(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        String rawKey = generateKey();

        ApiKey key = new ApiKey();
        key.setUser(user);
        key.setName(name.trim());
        key.setKeyPrefix(rawKey.substring(0, Math.min(rawKey.length(), 18)));
        key.setKeyHash(hash(rawKey));
        key.setCreatedAt(Instant.now());
        key = repository.save(key);

        ApiKeyCreatedResponse response = new ApiKeyCreatedResponse();
        response.setKey(ApiKeyResponse.from(key));
        response.setApiKey(rawKey);
        return response;
    }

    @Transactional
    public void revoke(Long userId, Long keyId) {
        ApiKey key = repository.findByIdAndUserUserId(keyId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("API key not found"));
        if (key.getRevokedAt() == null) {
            key.setRevokedAt(Instant.now());
            repository.save(key);
        }
    }

    @Transactional
    public Long authenticate(String rawKey) {
        return authenticateKey(rawKey).getUser().getUserId();
    }

    @Transactional
    public ApiKey authenticateKey(String rawKey) {
        if (rawKey == null || rawKey.isBlank() || !rawKey.startsWith(KEY_PREFIX)) {
            throw new UnauthorizedException("Invalid or missing API key");
        }
        ApiKey key = repository.findByKeyHashAndRevokedAtIsNull(hash(rawKey.trim()))
                .orElseThrow(() -> new UnauthorizedException("Invalid or revoked API key"));
        User user = key.getUser();
        if (!Boolean.TRUE.equals(user.getIsActive()) || !user.isVerified()) {
            throw new UnauthorizedException("API key account is unavailable");
        }
        key.setLastUsedAt(Instant.now());
        repository.save(key);
        return key;
    }

    @Transactional
    public void recordRequest(Long keyId, boolean successful) {
        repository.findById(keyId).ifPresent(key -> {
            if (successful) key.setSuccessfulRequests(key.getSuccessfulRequests() + 1);
            else key.setFailedRequests(key.getFailedRequests() + 1);
            repository.save(key);
        });
    }

    private String generateKey() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
