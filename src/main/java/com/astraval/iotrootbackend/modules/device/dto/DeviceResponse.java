package com.astraval.iotrootbackend.modules.device.dto;

import com.astraval.iotrootbackend.modules.device.Device;
import lombok.Data;

@Data
public class DeviceResponse {

    private Long id;
    private String clientId;
    private String username;
    private String mountpoint;

    public static DeviceResponse from(Device device) {
        DeviceResponse res = new DeviceResponse();
        res.setId(device.getId());
        res.setClientId(device.getClientId());
        res.setUsername(device.getUsername());
        res.setMountpoint(device.getMountpoint());
        return res;
    }
}
