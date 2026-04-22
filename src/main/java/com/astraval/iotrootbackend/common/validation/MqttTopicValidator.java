package com.astraval.iotrootbackend.common.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class MqttTopicValidator implements ConstraintValidator<ValidMqttTopic, String> {

    @Override
    public boolean isValid(String topic, ConstraintValidatorContext ctx) {
        if (topic == null || topic.isBlank()) return false;

        String[] levels = topic.split("/", -1);

        for (int i = 0; i < levels.length; i++) {
            String level = levels[i];

            // '#' must appear alone and only as the last level
            if (level.contains("#")) {
                if (!level.equals("#") || i != levels.length - 1) {
                    ctx.disableDefaultConstraintViolation();
                    ctx.buildConstraintViolationWithTemplate(
                        "'#' must be the last level and stand alone (e.g. sensors/# )"
                    ).addConstraintViolation();
                    return false;
                }
            }

            // '+' must occupy the entire level, not mixed with other chars
            if (level.contains("+") && !level.equals("+")) {
                ctx.disableDefaultConstraintViolation();
                ctx.buildConstraintViolationWithTemplate(
                    "'+' must stand alone within its level (e.g. sensors/+/temp)"
                ).addConstraintViolation();
                return false;
            }
        }

        return true;
    }
}
