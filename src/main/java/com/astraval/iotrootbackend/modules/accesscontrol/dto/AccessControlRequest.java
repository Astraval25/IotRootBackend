package com.astraval.iotrootbackend.modules.accesscontrol.dto;

import com.astraval.iotrootbackend.modules.accesscontrol.AccessControl.Permission;
import com.astraval.iotrootbackend.common.validation.ValidMqttTopic;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class AccessControlRequest {

    @NotBlank
    @ValidMqttTopic
    private String topic;

    @NotNull
    private Permission permission;
}
