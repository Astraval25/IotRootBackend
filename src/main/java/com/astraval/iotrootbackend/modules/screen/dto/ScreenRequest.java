package com.astraval.iotrootbackend.modules.screen.dto;

import com.astraval.iotrootbackend.common.validation.ValidMqttTopic;
import com.astraval.iotrootbackend.modules.screen.Screen.ActionType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class ScreenRequest {

    @NotBlank
    private String name;

    @NotBlank
    @ValidMqttTopic
    private String triggerTopic;

    @NotBlank
    @ValidMqttTopic
    private String targetTopic;

    @NotNull
    private ActionType actionType;

    private String payload;

    private Boolean active;
}

