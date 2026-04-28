package com.astraval.iotrootbackend.modules.device;

import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.modules.device.dto.DeviceRequest;
import com.astraval.iotrootbackend.modules.device.dto.DeviceConnectionStatusResponse;
import com.astraval.iotrootbackend.modules.device.dto.DeviceResponse;
import com.astraval.iotrootbackend.modules.user.User;
import com.astraval.iotrootbackend.modules.user.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class DeviceService {

    private final DeviceRepository deviceRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final VernemqSessionService vernemqSessionService;
    private final DeviceStatusPushService deviceStatusPushService;

    public DeviceService(DeviceRepository deviceRepository, UserService userService, PasswordEncoder passwordEncoder,
                         VernemqSessionService vernemqSessionService,
                         DeviceStatusPushService deviceStatusPushService) {
        this.deviceRepository = deviceRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.vernemqSessionService = vernemqSessionService;
        this.deviceStatusPushService = deviceStatusPushService;
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

    @Transactional(readOnly = true)
    public List<DeviceConnectionStatusResponse> getDeviceConnectionStatuses(String email) {
        User user = resolveUser(email);
        return getDeviceConnectionStatusesByUserId(user.getUserId());
    }

    @Transactional(readOnly = true)
    public List<DeviceConnectionStatusResponse> getDeviceConnectionStatusesByUserId(Long userId) {
        List<Device> devices = deviceRepository.findByUserUserId(userId);
        Map<String, Map<String, String>> sessionMap = vernemqSessionService.getSessionDetailsByClientId();

        return devices.stream().map(device -> {
            DeviceConnectionStatusResponse response = new DeviceConnectionStatusResponse();
            response.setDeviceId(device.getId());
            response.setClientId(device.getClientId());
            response.setUsername(device.getUsername());
            response.setBrokerHost(vernemqSessionService.getBrokerHost());
            response.setBrokerPort(vernemqSessionService.getBrokerPort());
            response.setStatusSource("vmq-admin session show --format=json");

            Map<String, String> details = sessionMap.getOrDefault(device.getClientId(), Map.of());
            boolean connected = !details.isEmpty() && Boolean.parseBoolean(details.getOrDefault("is_online", "false"));
            response.setConnected(connected);
            response.setNode(details.get("node"));
            response.setPeerHost(details.get("peer_host"));
            response.setPeerPort(parseInteger(details.get("peer_port")));
            response.setMountpoint(details.getOrDefault("mountpoint", device.getMountpoint()));
            response.setProtocol(details.get("proto_ver"));
            response.setKeepAlive(parseInteger(details.get("keep_alive")));
            response.setSessionExpiryInterval(parseInteger(details.get("expiry_interval")));
            response.setConnectedAt(details.get("connected_at"));
            response.setDisconnectedAt(details.get("disconnected_at"));
            response.setReason(details.get("reason"));
            response.setRawSummary(details.isEmpty() ? "No active session found for client_id" : details.toString());
            return response;
        }).toList();
    }

    @Transactional
    public DeviceResponse createDevice(DeviceRequest req, String email) {
        User user = resolveUser(email);
        Device device = new Device();
        device.setUser(user);
        device.setClientId(UUID.randomUUID().toString());
        applyRequest(device, req);
        DeviceResponse response = DeviceResponse.from(deviceRepository.save(device));
        pushLatestStatuses(user.getUserId());
        return response;
    }

    @Transactional
    public DeviceResponse updateDevice(Long id, DeviceRequest req, String email) {
        User user = resolveUser(email);
        Device device = resolveDevice(id, user.getUserId());
        applyRequest(device, req);
        DeviceResponse response = DeviceResponse.from(deviceRepository.save(device));
        pushLatestStatuses(user.getUserId());
        return response;
    }

    @Transactional
    public void deleteDevice(Long id, String email) {
        User user = resolveUser(email);
        deviceRepository.delete(resolveDevice(id, user.getUserId()));
        pushLatestStatuses(user.getUserId());
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

    private Integer parseInteger(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private void pushLatestStatuses(Long userId) {
        List<DeviceConnectionStatusResponse> statuses = getDeviceConnectionStatusesByUserId(userId);
        deviceStatusPushService.pushStatuses(userId, statuses, false);
    }
}
