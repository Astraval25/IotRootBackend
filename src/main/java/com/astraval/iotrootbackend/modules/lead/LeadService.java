package com.astraval.iotrootbackend.modules.lead;

import com.astraval.iotrootbackend.modules.lead.dto.LeadRequest;
import com.astraval.iotrootbackend.modules.lead.dto.LeadResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LeadService {

    private final LeadRepository leadRepository;

    public LeadService(LeadRepository leadRepository) {
        this.leadRepository = leadRepository;
    }

    @Transactional
    public LeadResponse createLead(LeadRequest request) {
        Lead lead = new Lead();
        lead.setName(request.getName().trim());
        lead.setEmail(request.getEmail().trim().toLowerCase());
        lead.setUseCase(request.getUseCase().trim());
        lead.setDeviceCount(request.getDeviceCount());

        return LeadResponse.from(leadRepository.save(lead));
    }
}
