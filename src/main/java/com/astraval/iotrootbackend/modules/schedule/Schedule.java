package com.astraval.iotrootbackend.modules.schedule;

import com.astraval.iotrootbackend.modules.screen.Screen;
import com.astraval.iotrootbackend.modules.user.User;
import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "schedules")
@Data
public class Schedule {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "schedule_seq")
    @SequenceGenerator(name = "schedule_seq", sequenceName = "schedules_id_seq", allocationSize = 1)
    @Column(name = "id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "screen_id")
    private Screen screen;

    @Column(name = "name", length = 120, nullable = false)
    private String name;

    @Column(name = "start_at", nullable = false)
    private Instant startAt;

    @Column(name = "end_at")
    private Instant endAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "recurrence_type", length = 20, nullable = false)
    private RecurrenceType recurrenceType;

    @Column(name = "interval_count", nullable = false)
    private Integer intervalCount = 1;

    @Column(name = "days_of_week", length = 50)
    private String daysOfWeek;

    @Column(name = "day_of_month")
    private Integer dayOfMonth;

    @Column(name = "timezone", length = 64, nullable = false)
    private String timezone = "UTC";

    @Column(name = "target_topic", length = 255)
    private String targetTopic;

    @Column(name = "payload", columnDefinition = "TEXT")
    private String payload;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "next_run_at")
    private Instant nextRunAt;

    @Column(name = "last_run_at")
    private Instant lastRunAt;

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
        if (intervalCount == null || intervalCount < 1) {
            intervalCount = 1;
        }
        if (timezone == null || timezone.isBlank()) {
            timezone = "UTC";
        }
        if (isActive == null) {
            isActive = true;
        }
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
        if (intervalCount == null || intervalCount < 1) {
            intervalCount = 1;
        }
        if (timezone == null || timezone.isBlank()) {
            timezone = "UTC";
        }
        if (isActive == null) {
            isActive = true;
        }
    }
}

