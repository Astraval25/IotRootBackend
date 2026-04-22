package com.astraval.iotrootbackend.modules.accesscontrol;

import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.modules.accesscontrol.dto.AccessControlRequest;
import com.astraval.iotrootbackend.modules.accesscontrol.dto.AccessControlResponse;
import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.device.DeviceService;
import com.astraval.iotrootbackend.modules.user.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AccessControlService {

    private final AccessControlRepository accessControlRepository;
    private final DeviceService deviceService;

    public AccessControlService(AccessControlRepository accessControlRepository, DeviceService deviceService) {
        this.accessControlRepository = accessControlRepository;
        this.deviceService = deviceService;
    }

    @Transactional(readOnly = true)
    public List<AccessControlResponse> getRules(Long deviceId, String email) {
        Long userId = resolveUserId(email);
        return accessControlRepository.findByDeviceIdAndDeviceUserUserId(deviceId, userId)
                .stream().map(AccessControlResponse::from).toList();
    }

    @Transactional
    public AccessControlResponse addRule(Long deviceId, AccessControlRequest req, String email) {
        User user = deviceService.resolveUser(email);
        Device device = deviceService.resolveDevice(deviceId, user.getUserId());
        AccessControl ac = new AccessControl();
        ac.setDevice(device);
        ac.setTopic(buildTopic(user.getUserId(), req.getTopic()));
        ac.setPermission(req.getPermission());
        return AccessControlResponse.from(accessControlRepository.save(ac));
    }

    @Transactional
    public AccessControlResponse updateRule(Long deviceId, Long ruleId, AccessControlRequest req, String email) {
        Long userId = resolveUserId(email);
        AccessControl ac = resolveRule(ruleId, deviceId, userId);
        ac.setTopic(buildTopic(userId, req.getTopic()));
        ac.setPermission(req.getPermission());
        return AccessControlResponse.from(accessControlRepository.save(ac));
    }

    @Transactional
    public void deleteRule(Long deviceId, Long ruleId, String email) {
        Long userId = resolveUserId(email);
        accessControlRepository.delete(resolveRule(ruleId, deviceId, userId));
    }

    private Long resolveUserId(String email) {
        return deviceService.resolveUser(email).getUserId();
    }

    private String buildTopic(Long userId, String userTopic) {
        return "/iot/" + userId + "/" + userTopic;
    }

    private AccessControl resolveRule(Long ruleId, Long deviceId, Long userId) {
        return accessControlRepository.findByIdAndDeviceIdAndDeviceUserUserId(ruleId, deviceId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Rule not found"));
    }
}
