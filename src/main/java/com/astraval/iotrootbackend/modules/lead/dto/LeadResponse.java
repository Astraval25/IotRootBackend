package com.astraval.iotrootbackend.modules.lead.dto;

import com.astraval.iotrootbackend.modules.lead.Lead;
import lombok.Data;

import java.time.Instant;

@Data
public class LeadResponse {

    private Long id;
    private String name;
    private String email;
    private String useCase;
    private Integer deviceCount;
    private Instant createdAt;

    public static LeadResponse from(Lead lead) {
        LeadResponse response = new LeadResponse();
        response.setId(lead.getId());
        response.setName(lead.getName());
        response.setEmail(lead.getEmail());
        response.setUseCase(lead.getUseCase());
        response.setDeviceCount(lead.getDeviceCount());
        response.setCreatedAt(lead.getCreatedAt());
        return response;
    }
}
