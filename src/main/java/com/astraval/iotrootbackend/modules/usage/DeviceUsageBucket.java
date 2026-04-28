package com.astraval.iotrootbackend.modules.usage;

import com.astraval.iotrootbackend.modules.device.Device;
import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "device_usage_buckets", indexes = {
        @Index(name = "idx_usage_device_bucket", columnList = "device_id,bucket_start"),
        @Index(name = "idx_usage_client_bucket", columnList = "client_id,bucket_start")
})
@Data
public class DeviceUsageBucket {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "usage_bucket_seq")
    @SequenceGenerator(name = "usage_bucket_seq", sequenceName = "device_usage_buckets_id_seq", allocationSize = 1)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_id", nullable = false)
    private Device device;

    @Column(name = "client_id", length = 128, nullable = false)
    private String clientId;

    @Column(name = "topic", length = 255, nullable = false)
    private String topic;

    @Enumerated(EnumType.STRING)
    @Column(name = "direction", length = 16, nullable = false)
    private UsageDirection direction;

    @Column(name = "bucket_start", nullable = false)
    private Instant bucketStart;

    @Column(name = "message_count", nullable = false)
    private Long messageCount = 0L;

    @Column(name = "payload_bytes", nullable = false)
    private Long payloadBytes = 0L;

    @Column(name = "estimated_total_bytes", nullable = false)
    private Long estimatedTotalBytes = 0L;
}
