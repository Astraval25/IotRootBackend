package com.astraval.iotrootbackend.modules.storeddata;

import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.user.User;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

@Entity
@Table(name = "mqtt_stored_messages", indexes = {
        @Index(name = "idx_store_user_received", columnList = "user_id,received_at"),
        @Index(name = "idx_store_device_received", columnList = "device_id,received_at"),
        @Index(name = "idx_store_user_topic_received", columnList = "user_id,topic,received_at")
})
@Data
public class StoredMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "stored_message_seq")
    @SequenceGenerator(name = "stored_message_seq", sequenceName = "mqtt_stored_messages_id_seq", allocationSize = 1)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "device_id", nullable = false)
    private Device device;

    @Column(name = "client_id", length = 128, nullable = false)
    private String clientId;

    @Column(name = "topic", length = 255, nullable = false)
    private String topic;

    @Column(name = "store_path", length = 255, nullable = false)
    private String storePath;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload", columnDefinition = "jsonb", nullable = false)
    private JsonNode payload;

    @Column(name = "payload_bytes", nullable = false)
    private Long payloadBytes;

    @Column(name = "qos")
    private Integer qos;

    @Column(name = "retained", nullable = false)
    private Boolean retained = false;

    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;
}
