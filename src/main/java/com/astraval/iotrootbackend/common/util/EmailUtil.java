package com.astraval.iotrootbackend.common.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class EmailUtil {

    @Autowired
    private JavaMailSender mailSender;

    public boolean sendTextEmail(String toEmail, String subject, String bodyText) {
        return sendTextEmail(null, toEmail, subject, bodyText);
    }

    public boolean sendTextEmail(String fromEmail, String toEmail, String subject, String bodyText) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            if (StringUtils.hasText(fromEmail)) {
                message.setFrom(fromEmail);
            }
            message.setTo(toEmail);
            message.setSubject(subject);
            message.setText(bodyText);
            mailSender.send(message);
        } catch (Exception e) {
            log.warn("Failed to send email to " + toEmail + ": " + e.getMessage());
            return false;
        }
        return true;
    }

    public boolean sendHtmlEmail(String toEmail, String subject, String bodyHtml) {
        return sendHtmlEmail(null, toEmail, subject, bodyHtml);
    }

    public boolean sendHtmlEmail(String fromEmail, String toEmail, String subject, String bodyHtml) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            if (StringUtils.hasText(fromEmail)) {
                helper.setFrom(fromEmail);
            }
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(bodyHtml, true);
            mailSender.send(message);
        } catch (Exception e) {
            log.warn("Failed to send email to " + toEmail + ": " + e.getMessage());
            return false;
        }
        return true;
    }
}
