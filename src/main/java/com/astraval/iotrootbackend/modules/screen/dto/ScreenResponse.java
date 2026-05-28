package com.astraval.iotrootbackend.modules.screen.dto;

import com.astraval.iotrootbackend.modules.screen.Screen;
import lombok.Data;

import java.time.Instant;

@Data
public class ScreenResponse {
    private Long id;
    private String name;
    private String triggerTopic;
    private String targetTopic;
    private String actionType;
    private String payload;
    private Boolean active;
    private Instant createdAt;
    private Instant updatedAt;

    public static ScreenResponse from(Screen screen) {
        ScreenResponse response = new ScreenResponse();
        response.setId(screen.getId());
        response.setName(screen.getName());
        response.setTriggerTopic(screen.getTriggerTopic());
        response.setTargetTopic(screen.getTargetTopic());
        response.setActionType(screen.getActionType().name());
        response.setPayload(screen.getPayload());
        response.setActive(screen.getIsActive());
        response.setCreatedAt(screen.getCreatedAt());
        response.setUpdatedAt(screen.getUpdatedAt());
        return response;
    }
}

