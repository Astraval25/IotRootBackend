package com.astraval.iotrootbackend.modules.auth.otp;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserOtpRepository extends JpaRepository<UserOtp, Long> {

    Optional<UserOtp> findTopByUserUserIdAndOtpCodeAndPurposeAndUsedFalseOrderByCreatedDtDesc(
            Long userId,
            String otpCode,
            OtpPurpose purpose);

    @Modifying
    @Query("""
            UPDATE UserOtp o
               SET o.used = true
             WHERE o.user.userId = :userId
               AND o.purpose = :purpose
               AND o.used = false
            """)
    int markAllUnusedAsUsed(@Param("userId") Long userId, @Param("purpose") OtpPurpose purpose);
}
