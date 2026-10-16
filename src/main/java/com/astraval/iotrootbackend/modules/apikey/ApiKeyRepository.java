package com.astraval.iotrootbackend.modules.apikey;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {
    List<ApiKey> findByUserUserIdOrderByCreatedAtDesc(Long userId);
    List<ApiKey> findByUserUserIdAndRevokedAtIsNullOrderByCreatedAtDesc(Long userId);
    Optional<ApiKey> findByIdAndUserUserId(Long id, Long userId);
    Optional<ApiKey> findByKeyHashAndRevokedAtIsNull(String keyHash);

    @Query("select coalesce(sum(k.successfulRequests), 0) from ApiKey k where k.user.userId = :userId")
    long sumSuccessfulRequestsByUserId(@Param("userId") Long userId);

    @Query("select coalesce(sum(k.failedRequests), 0) from ApiKey k where k.user.userId = :userId")
    long sumFailedRequestsByUserId(@Param("userId") Long userId);
}
