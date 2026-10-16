package com.astraval.iotrootbackend.modules.auth;

import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.astraval.iotrootbackend.modules.accesscontrol.AccessControl;
import com.astraval.iotrootbackend.modules.accesscontrol.AccessControlRepository;
import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.device.DeviceRepository;
import com.astraval.iotrootbackend.modules.user.User;

@Service
public class StarterWorkspaceProvisioner {

    static final String STARTER_TOPIC_PATH = "temperature";

    private final DeviceRepository deviceRepository;
    private final AccessControlRepository accessControlRepository;
    private final PasswordEncoder passwordEncoder;

    public StarterWorkspaceProvisioner(
            DeviceRepository deviceRepository,
            AccessControlRepository accessControlRepository,
            PasswordEncoder passwordEncoder) {
        this.deviceRepository = deviceRepository;
        this.accessControlRepository = accessControlRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public void provision(User user, String accountPassword) {
        String topic = starterTopic(user);
        Device device = deviceRepository.findByUserUserId(user.getUserId()).stream()
                .filter(candidate -> user.getEmail().equals(candidate.getUsername()))
                .findFirst()
                .orElseGet(() -> newStarterDevice(user));

        // Re-registering an unverified account replaces its account password. Keep
        // the automatically-created MQTT credentials in sync with that password.
        device.setPassword(passwordEncoder.encode(accountPassword));
        device = deviceRepository.save(device);

        if (!accessControlRepository.existsByDeviceIdAndTopic(device.getId(), topic)) {
            AccessControl accessControl = new AccessControl();
            accessControl.setDevice(device);
            accessControl.setTopic(topic);
            accessControl.setPermission(AccessControl.Permission.publish);
            accessControlRepository.save(accessControl);
        }
    }

    public void rotatePasswordIfPresent(User user, String accountPassword) {
        accessControlRepository.findFirstByDeviceUserUserIdAndTopicOrderByIdAsc(user.getUserId(), starterTopic(user))
                .map(AccessControl::getDevice)
                .ifPresent(device -> {
                    device.setPassword(passwordEncoder.encode(accountPassword));
                    deviceRepository.save(device);
                });
    }

    private Device newStarterDevice(User user) {
        Device device = new Device();
        device.setUser(user);
        device.setClientId(UUID.randomUUID().toString());
        device.setUsername(user.getEmail());
        device.setMountpoint("");
        return device;
    }

    private String starterTopic(User user) {
        return "/iot/store/" + user.getUserId() + "/" + STARTER_TOPIC_PATH;
    }
}
