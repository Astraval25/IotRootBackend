package com.astraval.iotrootbackend.modules.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.astraval.iotrootbackend.modules.accesscontrol.AccessControl;
import com.astraval.iotrootbackend.modules.accesscontrol.AccessControlRepository;
import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.device.DeviceRepository;
import com.astraval.iotrootbackend.modules.user.User;

class StarterWorkspaceProvisionerTest {

    @Test
    void createsADeviceAndPublishableStoredTemperatureTopic() {
        DeviceRepository devices = mock(DeviceRepository.class);
        AccessControlRepository accessControls = mock(AccessControlRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        StarterWorkspaceProvisioner provisioner = new StarterWorkspaceProvisioner(devices, accessControls, encoder);
        User user = user(42L, "maker@example.com");

        when(devices.findByUserUserId(42L)).thenReturn(List.of());
        when(encoder.encode("account-secret")).thenReturn("encoded-secret");
        when(devices.save(any(Device.class))).thenAnswer(invocation -> {
            Device device = invocation.getArgument(0);
            device.setId(7L);
            return device;
        });
        when(accessControls.existsByDeviceIdAndTopic(7L, "/iot/store/42/temperature")).thenReturn(false);

        provisioner.provision(user, "account-secret");

        ArgumentCaptor<Device> deviceCaptor = ArgumentCaptor.forClass(Device.class);
        verify(devices).save(deviceCaptor.capture());
        Device device = deviceCaptor.getValue();
        assertEquals("maker@example.com", device.getUsername());
        assertEquals("encoded-secret", device.getPassword());
        assertEquals("", device.getMountpoint());
        assertNotNull(device.getClientId());

        ArgumentCaptor<AccessControl> ruleCaptor = ArgumentCaptor.forClass(AccessControl.class);
        verify(accessControls).save(ruleCaptor.capture());
        assertEquals(device, ruleCaptor.getValue().getDevice());
        assertEquals("/iot/store/42/temperature", ruleCaptor.getValue().getTopic());
        assertEquals(AccessControl.Permission.publish, ruleCaptor.getValue().getPermission());
    }

    @Test
    void reusesTheStarterDeviceAndDoesNotDuplicateItsTopic() {
        DeviceRepository devices = mock(DeviceRepository.class);
        AccessControlRepository accessControls = mock(AccessControlRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        StarterWorkspaceProvisioner provisioner = new StarterWorkspaceProvisioner(devices, accessControls, encoder);
        User user = user(42L, "maker@example.com");
        Device existing = new Device();
        existing.setId(7L);
        existing.setUser(user);
        existing.setUsername(user.getEmail());
        existing.setClientId("existing-client-id");

        when(devices.findByUserUserId(42L)).thenReturn(List.of(existing));
        when(encoder.encode("new-secret")).thenReturn("new-encoded-secret");
        when(devices.save(existing)).thenReturn(existing);
        when(accessControls.existsByDeviceIdAndTopic(7L, "/iot/store/42/temperature")).thenReturn(true);

        provisioner.provision(user, "new-secret");

        assertEquals("new-encoded-secret", existing.getPassword());
        assertEquals("existing-client-id", existing.getClientId());
        verify(accessControls, never()).save(any());
    }

    @Test
    void keepsTheExistingStarterDeviceInSyncAfterAnAccountPasswordReset() {
        DeviceRepository devices = mock(DeviceRepository.class);
        AccessControlRepository accessControls = mock(AccessControlRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        StarterWorkspaceProvisioner provisioner = new StarterWorkspaceProvisioner(devices, accessControls, encoder);
        User user = user(42L, "maker@example.com");
        Device existing = new Device();
        existing.setId(7L);
        existing.setUser(user);
        AccessControl starterRule = new AccessControl();
        starterRule.setDevice(existing);

        when(accessControls.findFirstByDeviceUserUserIdAndTopicOrderByIdAsc(42L, "/iot/store/42/temperature"))
                .thenReturn(Optional.of(starterRule));
        when(encoder.encode("reset-secret")).thenReturn("reset-encoded-secret");

        provisioner.rotatePasswordIfPresent(user, "reset-secret");

        assertEquals("reset-encoded-secret", existing.getPassword());
        verify(devices).save(existing);
    }

    private User user(Long id, String email) {
        User user = new User();
        user.setUserId(id);
        user.setEmail(email);
        return user;
    }
}
