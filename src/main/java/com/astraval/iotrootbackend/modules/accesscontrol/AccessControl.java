package com.astraval.iotrootbackend.modules.accesscontrol;

import com.astraval.iotrootbackend.modules.device.Device;
import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "access_controls")
@Data
public class AccessControl {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "access_control_seq")
    @SequenceGenerator(name = "access_control_seq", sequenceName = "access_controls_id_seq", allocationSize = 1)
    @Column(name = "id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_id", nullable = false)
    private Device device;

    @Column(name = "topic", length = 255, nullable = false)
    private String topic;

    @Enumerated(EnumType.STRING)
    @Column(name = "permission", length = 10, nullable = false)
    private Permission permission;

    public enum Permission {
        publish, subscribe, readwrite
    }
}
