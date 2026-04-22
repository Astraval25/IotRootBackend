package com.astraval.iotrootbackend.modules.device;

import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.modules.device.dto.DeviceRequest;
import com.astraval.iotrootbackend.modules.device.dto.DeviceResponse;
import com.astraval.iotrootbackend.modules.user.User;
import com.astraval.iotrootbackend.modules.user.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
public class DeviceService {

    private final DeviceRepository deviceRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public DeviceService(DeviceRepository deviceRepository, UserService userService, PasswordEncoder passwordEncoder) {
        this.deviceRepository = deviceRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public List<DeviceResponse> getDevices(String email) {
        User user = resolveUser(email);
        return deviceRepository.findByUserUserId(user.getUserId())
                .stream().map(DeviceResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public DeviceResponse getDevice(Long id, String email) {
        User user = resolveUser(email);
        return DeviceResponse.from(resolveDevice(id, user.getUserId()));
    }

    @Transactional
    public DeviceResponse createDevice(DeviceRequest req, String email) {
        User user = resolveUser(email);
        Device device = new Device();
        device.setUser(user);
        device.setClientId(UUID.randomUUID().toString());
        applyRequest(device, req);
        return DeviceResponse.from(deviceRepository.save(device));
    }

    @Transactional
    public DeviceResponse updateDevice(Long id, DeviceRequest req, String email) {
        User user = resolveUser(email);
        Device device = resolveDevice(id, user.getUserId());
        applyRequest(device, req);
        return DeviceResponse.from(deviceRepository.save(device));
    }

    @Transactional
    public void deleteDevice(Long id, String email) {
        User user = resolveUser(email);
        deviceRepository.delete(resolveDevice(id, user.getUserId()));
    }

    public Device resolveDevice(Long id, Long userId) {
        return deviceRepository.findByIdAndUserUserId(id, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Device not found"));
    }

    public User resolveUser(String sub) {
        return userService.findUserById(Long.parseLong(sub))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    private void applyRequest(Device device, DeviceRequest req) {
        device.setUsername(req.getUsername());
        if (req.getPassword() != null) {
            device.setPassword(passwordEncoder.encode(req.getPassword()));
        }
        device.setMountpoint(req.getMountpoint() != null ? req.getMountpoint() : "");
    }
}
