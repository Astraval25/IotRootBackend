package com.astraval.iotrootbackend.modules.emailtemplate;

import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.astraval.iotrootbackend.common.exception.BadRequestException;
import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.common.util.EmailUtil;

@Service
public class EmailTemplateService {

    private final EmailTemplateRepository emailTemplateRepository;
    private final EmailUtil emailUtil;

    public EmailTemplateService(EmailTemplateRepository emailTemplateRepository, EmailUtil emailUtil) {
        this.emailTemplateRepository = emailTemplateRepository;
        this.emailUtil = emailUtil;
    }

    public boolean sendTemplatedEmail(String templateName, String toEmail, Map<String, String> placeholders) {
        EmailTemplate template = emailTemplateRepository.findByNameIgnoreCaseAndIsActiveTrue(templateName)
                .orElseThrow(() -> new ResourceNotFoundException("Email template not found: " + templateName));

        String recipient = StringUtils.hasText(toEmail) ? toEmail : template.getToEmail();
        if (!StringUtils.hasText(recipient)) {
            throw new BadRequestException("Recipient email is required");
        }

        String subject = render(template.getSubject(), placeholders);
        String bodyText = render(template.getBodyText(), placeholders);
        String bodyHtml = render(template.getBodyHtml(), placeholders);
        String fromEmail = StringUtils.hasText(template.getFromEmail()) ? template.getFromEmail() : null;

        if (StringUtils.hasText(bodyHtml)) {
            return emailUtil.sendHtmlEmail(fromEmail, recipient, subject, bodyHtml);
        }
        if (StringUtils.hasText(bodyText)) {
            return emailUtil.sendTextEmail(fromEmail, recipient, subject, bodyText);
        }

        throw new BadRequestException("Email template has no content: " + templateName);
    }

    private String render(String source, Map<String, String> placeholders) {
        if (source == null) {
            return null;
        }
        String rendered = source;
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            String key = "{{" + entry.getKey() + "}}";
            rendered = rendered.replace(key, entry.getValue() == null ? "" : entry.getValue());
        }
        return rendered;
    }
}
