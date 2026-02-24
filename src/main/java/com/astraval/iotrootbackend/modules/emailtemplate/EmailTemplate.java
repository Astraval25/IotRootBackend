package com.astraval.iotrootbackend.modules.emailtemplate;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "email_templates")
public class EmailTemplate {

    @Id
    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "from_email", length = 150)
    private String fromEmail;

    @Column(name = "to_email", length = 150)
    private String toEmail;

    @Column(name = "subject", length = 200)
    private String subject;

    @Column(name = "body_html", columnDefinition = "TEXT")
    private String bodyHtml;

    @Column(name = "body_text", columnDefinition = "TEXT")
    private String bodyText;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "type", length = 100)
    private String type;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "created_by")
    private Long createdBy;

    @Column(name = "created_dt")
    private LocalDateTime createdDt;

    @Column(name = "modified_by")
    private Long modifiedBy;

    @Column(name = "modified_dt")
    private LocalDateTime modifiedDt;
}
