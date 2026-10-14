package com.astraval.iotrootbackend.modules.storeddata;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;

public interface StoredMessageRepository extends JpaRepository<StoredMessage, Long>,
        JpaSpecificationExecutor<StoredMessage> {

    long countByUserUserIdAndReceivedAtBetween(Long userId, Instant from, Instant to);

    long countByUserUserId(Long userId);

    @Query("""
            select coalesce(sum(m.payloadBytes), 0)
            from StoredMessage m
            where m.user.userId = :userId
              and m.receivedAt between :from and :to
            """)
    Long sumPayloadBytesByUserAndRange(Long userId, Instant from, Instant to);

    @Query("""
            select coalesce(sum(m.payloadBytes), 0)
            from StoredMessage m
            where m.user.userId = :userId
            """)
    Long sumPayloadBytesByUser(Long userId);

    @Modifying
    @Query("delete from StoredMessage m where m.device.id = :deviceId")
    void deleteByDeviceId(Long deviceId);
}
