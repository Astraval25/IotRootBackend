package com.astraval.iotrootbackend.common.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = MqttTopicValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidMqttTopic {
    String message() default "Invalid MQTT topic";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
