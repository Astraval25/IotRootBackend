package com.astraval.iotrootbackend.modules.device;

import com.astraval.iotrootbackend.modules.accesscontrol.AccessControl;
import com.astraval.iotrootbackend.modules.user.User;
import jakarta.persistence.*;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(
    name = "devices",
    uniqueConstraints = @UniqueConstraint(
        name = "devices_mountpoint_client_id_username_key",
        columnNames = {"mountpoint", "client_id", "username"}
    )
)
@Data
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "device_seq")
    @SequenceGenerator(name = "device_seq", sequenceName = "devices_id_seq", allocationSize = 1)
    @Column(name = "id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "mountpoint", length = 10, nullable = false)
    private String mountpoint = "";

    @Column(name = "client_id", length = 128, nullable = false)
    private String clientId;

    @Column(name = "username", length = 128, nullable = false)
    private String username;

    @Column(name = "password", length = 128)
    private String password;

    @OneToMany(mappedBy = "device", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<AccessControl> accessControls = new ArrayList<>();
}
