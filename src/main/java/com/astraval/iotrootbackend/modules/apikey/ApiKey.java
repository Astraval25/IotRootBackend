package com.astraval.iotrootbackend.modules.apikey;

import com.astraval.iotrootbackend.modules.user.User;
import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "api_keys", indexes = {
        @Index(name = "idx_api_key_user", columnList = "user_id"),
        @Index(name = "idx_api_key_hash", columnList = "key_hash", unique = true)
})
@Data
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "api_key_seq")
    @SequenceGenerator(name = "api_key_seq", sequenceName = "api_keys_id_seq", allocationSize = 1)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "name", length = 80, nullable = false)
    private String name;

    @Column(name = "key_prefix", length = 24, nullable = false)
    private String keyPrefix;

    @Column(name = "key_hash", length = 64, nullable = false, unique = true)
    private String keyHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;
}
