package com.astraval.iotrootbackend.modules.user;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Data;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Table(name = "users", uniqueConstraints = @UniqueConstraint(name = "uk_users_email", columnNames = "email"))
@EntityListeners(AuditingEntityListener.class)
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "user_seq")
    @SequenceGenerator(name = "user_seq", sequenceName = "users_user_id_seq", allocationSize = 1)
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "password", length = 300, nullable = false)
    private String password;

    @Column(name = "email", length = 100, nullable = false, unique = true)
    private String email;

    @Column(name = "verified")
    private boolean verified = false;

    // default fields...
    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @CreatedBy
    @Column(name = "created_by")
    private Long createdBy;

    @CreatedDate
    @Column(name = "created_dt", nullable = false)
    private LocalDateTime createdDt;

    @LastModifiedBy
    @Column(name = "modified_by")
    private Long lastModifiedBy;

    @LastModifiedDate
    @Column(name = "modified_dt")
    private LocalDateTime lastModifiedDt;

    @PrePersist
    void onCreate() {
        if (createdDt == null) {
            createdDt = LocalDateTime.now();
        }
        if (isActive == null) {
            isActive = true;
        }
    }

    @PreUpdate
    void onUpdate() {
        lastModifiedDt = LocalDateTime.now();
        if (isActive == null) {
            isActive = true;
        }
    }

}
