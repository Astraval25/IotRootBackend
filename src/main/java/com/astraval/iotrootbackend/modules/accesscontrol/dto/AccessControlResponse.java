package com.astraval.iotrootbackend.modules.accesscontrol.dto;

import com.astraval.iotrootbackend.modules.accesscontrol.AccessControl;
import lombok.Data;

@Data
public class AccessControlResponse {

    private Long id;
    private Long deviceId;
    private String topic;
    private String permission;

    public static AccessControlResponse from(AccessControl ac) {
        AccessControlResponse res = new AccessControlResponse();
        res.setId(ac.getId());
        res.setDeviceId(ac.getDevice().getId());
        res.setTopic(stripPrefix(ac.getDevice().getUser().getUserId(), ac.getTopic()));
        res.setPermission(ac.getPermission().name());
        return res;
    }

    private static String stripPrefix(Long userId, String storedTopic) {
        String prefix = "/iot/" + userId + "/";
        return storedTopic.startsWith(prefix) ? storedTopic.substring(prefix.length()) : storedTopic;
    }
}
