package com.astraval.iotrootbackend.modules.emailtemplate;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EmailTemplateRepository extends JpaRepository<EmailTemplate, String> {

    Optional<EmailTemplate> findByNameIgnoreCaseAndIsActiveTrue(String name);
}
