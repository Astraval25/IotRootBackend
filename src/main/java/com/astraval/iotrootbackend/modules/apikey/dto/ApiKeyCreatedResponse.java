package com.astraval.iotrootbackend.modules.apikey.dto;

import lombok.Data;

@Data
public class ApiKeyCreatedResponse {
    private ApiKeyResponse key;
    private String apiKey;
}
