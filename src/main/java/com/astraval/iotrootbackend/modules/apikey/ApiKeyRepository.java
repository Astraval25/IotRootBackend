package com.astraval.iotrootbackend.modules.apikey;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {
    List<ApiKey> findByUserUserIdOrderByCreatedAtDesc(Long userId);
    Optional<ApiKey> findByIdAndUserUserId(Long id, Long userId);
    Optional<ApiKey> findByKeyHashAndRevokedAtIsNull(String keyHash);
}
