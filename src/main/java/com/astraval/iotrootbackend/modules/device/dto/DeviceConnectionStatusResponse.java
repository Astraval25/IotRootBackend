package com.astraval.iotrootbackend.modules.device.dto;

import lombok.Data;

@Data
public class DeviceConnectionStatusResponse {

    private Long deviceId;
    private String clientId;
    private String username;
    private boolean connected;
    private String node;
    private String peerHost;
    private Integer peerPort;
    private String mountpoint;
    private String protocol;
    private Integer keepAlive;
    private Integer sessionExpiryInterval;
    private String connectedAt;
    private String disconnectedAt;
    private String reason;
    private String brokerHost;
    private Integer brokerPort;
    private String statusSource;
    private String rawSummary;
}
