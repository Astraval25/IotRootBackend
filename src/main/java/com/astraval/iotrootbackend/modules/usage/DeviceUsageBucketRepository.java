package com.astraval.iotrootbackend.modules.usage;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface DeviceUsageBucketRepository extends JpaRepository<DeviceUsageBucket, Long> {

    Optional<DeviceUsageBucket> findByDeviceIdAndTopicAndDirectionAndBucketStart(
            Long deviceId, String topic, UsageDirection direction, Instant bucketStart
    );

    @Query("""
            select b from DeviceUsageBucket b
            where b.device.id = :deviceId
            and b.bucketStart between :from and :to
            order by b.bucketStart asc
            """)
    List<DeviceUsageBucket> findByDeviceAndRange(Long deviceId, Instant from, Instant to);

    @Query("""
            select b from DeviceUsageBucket b
            where b.device.user.userId = :userId
            and b.bucketStart between :from and :to
            order by b.bucketStart asc
            """)
    List<DeviceUsageBucket> findByUserAndRange(Long userId, Instant from, Instant to);
}
