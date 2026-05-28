package com.astraval.iotrootbackend.modules.schedule.dto;

import com.astraval.iotrootbackend.modules.schedule.Schedule;
import lombok.Data;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Data
public class ScheduleResponse {
    private Long id;
    private String name;
    private Instant startAt;
    private Instant endAt;
    private String recurrenceType;
    private Integer intervalCount;
    private List<String> daysOfWeek;
    private Integer dayOfMonth;
    private String timezone;
    private Long screenId;
    private String targetTopic;
    private String payload;
    private Boolean active;
    private Instant nextRunAt;
    private Instant lastRunAt;
    private Instant createdAt;
    private Instant updatedAt;

    public static ScheduleResponse from(Schedule schedule) {
        ScheduleResponse response = new ScheduleResponse();
        response.setId(schedule.getId());
        response.setName(schedule.getName());
        response.setStartAt(schedule.getStartAt());
        response.setEndAt(schedule.getEndAt());
        response.setRecurrenceType(schedule.getRecurrenceType().name());
        response.setIntervalCount(schedule.getIntervalCount());
        response.setDaysOfWeek(parseDays(schedule.getDaysOfWeek()));
        response.setDayOfMonth(schedule.getDayOfMonth());
        response.setTimezone(schedule.getTimezone());
        response.setScreenId(schedule.getScreen() != null ? schedule.getScreen().getId() : null);
        response.setTargetTopic(schedule.getTargetTopic());
        response.setPayload(schedule.getPayload());
        response.setActive(schedule.getIsActive());
        response.setNextRunAt(schedule.getNextRunAt());
        response.setLastRunAt(schedule.getLastRunAt());
        response.setCreatedAt(schedule.getCreatedAt());
        response.setUpdatedAt(schedule.getUpdatedAt());
        return response;
    }

    private static List<String> parseDays(String daysOfWeek) {
        if (daysOfWeek == null || daysOfWeek.isBlank()) {
            return List.of();
        }
        return Arrays.stream(daysOfWeek.split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .toList();
    }
}

