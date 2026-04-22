package com.astraval.iotrootbackend.modules.device.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DeviceRequest {

    @NotBlank
    private String username;

    private String password;

    private String mountpoint = "";
}
