package com.astraval.iotrootbackend.modules.schedule.dto;

import com.astraval.iotrootbackend.modules.schedule.RecurrenceType;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.DayOfWeek;
import java.time.Instant;
import java.util.List;

@Data
public class ScheduleRequest {

    @NotBlank
    private String name;

    @NotNull
    private Instant startAt;

    private Instant endAt;

    @NotNull
    private RecurrenceType recurrenceType;

    @Min(1)
    private Integer intervalCount = 1;

    private List<DayOfWeek> daysOfWeek;

    private Integer dayOfMonth;

    private String timezone;

    private Long screenId;

    private String targetTopic;

    private String payload;

    private Boolean active;
}
