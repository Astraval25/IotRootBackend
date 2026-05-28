package com.astraval.iotrootbackend.modules.screen;

import com.astraval.iotrootbackend.modules.user.User;
import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "screens")
@Data
public class Screen {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "screen_seq")
    @SequenceGenerator(name = "screen_seq", sequenceName = "screens_id_seq", allocationSize = 1)
    @Column(name = "id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "name", length = 120, nullable = false)
    private String name;

    @Column(name = "trigger_topic", length = 255, nullable = false)
    private String triggerTopic;

    @Column(name = "target_topic", length = 255, nullable = false)
    private String targetTopic;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_type", length = 20, nullable = false)
    private ActionType actionType;

    @Column(name = "payload", columnDefinition = "TEXT")
    private String payload;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
        if (isActive == null) {
            isActive = true;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
        if (isActive == null) {
            isActive = true;
        }
    }

    public enum ActionType {
        CONTROL,
        MESSAGE
    }
}

