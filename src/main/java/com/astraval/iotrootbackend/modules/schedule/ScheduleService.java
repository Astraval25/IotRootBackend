package com.astraval.iotrootbackend.modules.schedule;

import com.astraval.iotrootbackend.common.exception.BadRequestException;
import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.modules.device.DeviceService;
import com.astraval.iotrootbackend.modules.schedule.dto.ScheduleRequest;
import com.astraval.iotrootbackend.modules.schedule.dto.ScheduleResponse;
import com.astraval.iotrootbackend.modules.screen.Screen;
import com.astraval.iotrootbackend.modules.screen.ScreenService;
import com.astraval.iotrootbackend.modules.user.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAdjusters;
import java.util.*;

@Service
public class ScheduleService {

    private final ScheduleRepository scheduleRepository;
    private final DeviceService deviceService;
    private final ScreenService screenService;

    public ScheduleService(ScheduleRepository scheduleRepository, DeviceService deviceService, ScreenService screenService) {
        this.scheduleRepository = scheduleRepository;
        this.deviceService = deviceService;
        this.screenService = screenService;
    }

    @Transactional(readOnly = true)
    public List<ScheduleResponse> getSchedules(String sub) {
        Long userId = resolveUser(sub).getUserId();
        return scheduleRepository.findByUserUserIdOrderByUpdatedAtDesc(userId)
                .stream().map(ScheduleResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public ScheduleResponse getSchedule(Long id, String sub) {
        Long userId = resolveUser(sub).getUserId();
        return ScheduleResponse.from(resolveSchedule(id, userId));
    }

    @Transactional
    public ScheduleResponse createSchedule(ScheduleRequest req, String sub) {
        User user = resolveUser(sub);
        Schedule schedule = new Schedule();
        schedule.setUser(user);
        applyRequest(schedule, req, user.getUserId());
        return ScheduleResponse.from(scheduleRepository.save(schedule));
    }

    @Transactional
    public ScheduleResponse updateSchedule(Long id, ScheduleRequest req, String sub) {
        User user = resolveUser(sub);
        Schedule schedule = resolveSchedule(id, user.getUserId());
        applyRequest(schedule, req, user.getUserId());
        return ScheduleResponse.from(scheduleRepository.save(schedule));
    }

    @Transactional
    public void deleteSchedule(Long id, String sub) {
        Long userId = resolveUser(sub).getUserId();
        scheduleRepository.delete(resolveSchedule(id, userId));
    }

    private User resolveUser(String sub) {
        return deviceService.resolveUser(sub);
    }

    private Schedule resolveSchedule(Long id, Long userId) {
        return scheduleRepository.findByIdAndUserUserId(id, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Schedule not found"));
    }

    private void applyRequest(Schedule schedule, ScheduleRequest req, Long userId) {
        validateRequest(req);
        Screen screen = resolveScreen(req.getScreenId(), userId);
        schedule.setScreen(screen);
        schedule.setName(req.getName().trim());
        schedule.setStartAt(req.getStartAt());
        schedule.setEndAt(req.getEndAt());
        schedule.setRecurrenceType(req.getRecurrenceType());
        schedule.setIntervalCount(req.getIntervalCount() == null ? 1 : req.getIntervalCount());
        schedule.setDaysOfWeek(req.getRecurrenceType() == RecurrenceType.WEEKLY ? toCsvDays(req.getDaysOfWeek()) : null);
        schedule.setDayOfMonth(req.getRecurrenceType() == RecurrenceType.MONTHLY ? req.getDayOfMonth() : null);
        schedule.setTimezone(resolveZone(req.getTimezone()).getId());
        schedule.setTargetTopic(req.getTargetTopic() == null || req.getTargetTopic().isBlank()
                ? null
                : buildTopic(userId, req.getTargetTopic()));
        schedule.setPayload(req.getPayload());
        schedule.setIsActive(req.getActive() == null ? true : req.getActive());
        schedule.setNextRunAt(computeNextRunAt(schedule, Instant.now()));
    }

    private Screen resolveScreen(Long screenId, Long userId) {
        if (screenId == null) {
            return null;
        }
        return screenService.resolveScreen(screenId, userId);
    }

    private void validateRequest(ScheduleRequest req) {
        if (req.getEndAt() != null && req.getEndAt().isBefore(req.getStartAt())) {
            throw new BadRequestException("endAt must be after startAt");
        }
        if (req.getScreenId() == null && (req.getTargetTopic() == null || req.getTargetTopic().isBlank())) {
            throw new BadRequestException("Either screenId or targetTopic is required");
        }
        if (req.getTargetTopic() != null && !req.getTargetTopic().isBlank() && !isValidTopic(req.getTargetTopic())) {
            throw new BadRequestException("Invalid MQTT topic");
        }
        if (req.getRecurrenceType() == RecurrenceType.WEEKLY) {
            if (req.getDaysOfWeek() == null || req.getDaysOfWeek().isEmpty()) {
                throw new BadRequestException("daysOfWeek is required for WEEKLY recurrence");
            }
        }
        if (req.getRecurrenceType() == RecurrenceType.MONTHLY) {
            if (req.getDayOfMonth() == null || req.getDayOfMonth() < 1 || req.getDayOfMonth() > 31) {
                throw new BadRequestException("dayOfMonth must be between 1 and 31 for MONTHLY recurrence");
            }
        }
        if (req.getIntervalCount() != null && req.getIntervalCount() < 1) {
            throw new BadRequestException("intervalCount must be at least 1");
        }
        if (req.getTimezone() != null && !req.getTimezone().isBlank()) {
            try {
                ZoneId.of(req.getTimezone());
            } catch (Exception ex) {
                throw new BadRequestException("Invalid timezone");
            }
        }
    }

    private boolean isValidTopic(String topic) {
        String[] levels = topic.split("/", -1);
        for (int i = 0; i < levels.length; i++) {
            String level = levels[i];
            if (level.contains("#")) {
                if (!level.equals("#") || i != levels.length - 1) {
                    return false;
                }
            }
            if (level.contains("+") && !level.equals("+")) {
                return false;
            }
        }
        return true;
    }

    private String toCsvDays(List<DayOfWeek> daysOfWeek) {
        if (daysOfWeek == null || daysOfWeek.isEmpty()) {
            return null;
        }
        return daysOfWeek.stream()
                .distinct()
                .sorted(Comparator.comparingInt(DayOfWeek::getValue))
                .map(Enum::name)
                .reduce((left, right) -> left + "," + right)
                .orElse(null);
    }

    private Set<DayOfWeek> parseDays(String csv) {
        if (csv == null || csv.isBlank()) {
            return Set.of();
        }
        Set<DayOfWeek> result = new HashSet<>();
        for (String token : csv.split(",")) {
            String normalized = token.trim();
            if (normalized.isEmpty()) {
                continue;
            }
            result.add(DayOfWeek.valueOf(normalized));
        }
        return result;
    }

    private ZoneId resolveZone(String timezone) {
        if (timezone == null || timezone.isBlank()) {
            return ZoneId.of("UTC");
        }
        return ZoneId.of(timezone);
    }

    private String buildTopic(Long userId, String userTopic) {
        return "/iot/" + userId + "/" + userTopic;
    }

    private Instant computeNextRunAt(Schedule schedule, Instant from) {
        if (Boolean.FALSE.equals(schedule.getIsActive())) {
            return null;
        }

        ZoneId zone = resolveZone(schedule.getTimezone());
        ZonedDateTime start = schedule.getStartAt().atZone(zone);
        ZonedDateTime cursor = from.isAfter(schedule.getStartAt()) ? from.atZone(zone).plusSeconds(1) : start;

        ZonedDateTime next = switch (schedule.getRecurrenceType()) {
            case ONCE -> computeOnce(start, cursor);
            case DAILY -> computeDaily(start, cursor, schedule.getIntervalCount());
            case WEEKLY -> computeWeekly(start, cursor, schedule.getIntervalCount(), parseDays(schedule.getDaysOfWeek()));
            case MONTHLY -> computeMonthly(start, cursor, schedule.getIntervalCount(), schedule.getDayOfMonth());
        };

        if (next == null) {
            return null;
        }
        Instant nextInstant = next.toInstant();
        if (schedule.getEndAt() != null && nextInstant.isAfter(schedule.getEndAt())) {
            return null;
        }
        return nextInstant;
    }

    private ZonedDateTime computeOnce(ZonedDateTime start, ZonedDateTime cursor) {
        return start.isAfter(cursor.minusSeconds(1)) ? start : null;
    }

    private ZonedDateTime computeDaily(ZonedDateTime start, ZonedDateTime cursor, Integer interval) {
        int daysInterval = interval == null ? 1 : interval;
        ZonedDateTime candidate = start;
        while (!candidate.isAfter(cursor.minusSeconds(1))) {
            candidate = candidate.plusDays(daysInterval);
        }
        return candidate;
    }

    private ZonedDateTime computeWeekly(ZonedDateTime start, ZonedDateTime cursor, Integer interval, Set<DayOfWeek> days) {
        if (days == null || days.isEmpty()) {
            days = Set.of(start.getDayOfWeek());
        }
        int weekInterval = interval == null ? 1 : interval;
        ZonedDateTime candidate = cursor;
        candidate = candidate.withHour(start.getHour())
                .withMinute(start.getMinute())
                .withSecond(start.getSecond())
                .withNano(start.getNano());
        if (candidate.isBefore(start)) {
            candidate = start;
        }

        LocalDate startAnchor = start.toLocalDate().with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
        for (int i = 0; i < 3700; i++) {
            if (!candidate.isBefore(start)
                    && candidate.isAfter(cursor.minusSeconds(1))
                    && days.contains(candidate.getDayOfWeek())) {
                LocalDate candidateAnchor = candidate.toLocalDate().with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
                long weekDiff = ChronoUnit.WEEKS.between(startAnchor, candidateAnchor);
                if (weekDiff >= 0 && weekDiff % weekInterval == 0) {
                    return candidate;
                }
            }
            candidate = candidate.plusDays(1);
        }
        return null;
    }

    private ZonedDateTime computeMonthly(ZonedDateTime start, ZonedDateTime cursor, Integer interval, Integer dayOfMonth) {
        int monthInterval = interval == null ? 1 : interval;
        int targetDay = dayOfMonth == null ? start.getDayOfMonth() : dayOfMonth;
        if (targetDay < 1 || targetDay > 31) {
            return null;
        }

        ZonedDateTime base = start.withDayOfMonth(1);
        int startMonthOffset = 0;
        if (cursor.isAfter(start)) {
            startMonthOffset = (int) ChronoUnit.MONTHS.between(
                    YearMonth.from(base),
                    YearMonth.from(cursor.withDayOfMonth(1))
            );
            if (startMonthOffset < 0) {
                startMonthOffset = 0;
            }
        }
        int alignedOffset = (startMonthOffset / monthInterval) * monthInterval;

        for (int i = 0; i < 2400; i++) {
            YearMonth ym = YearMonth.from(base.plusMonths((long) alignedOffset + (long) i * monthInterval));
            int safeDay = Math.min(targetDay, ym.lengthOfMonth());
            ZonedDateTime candidate = ym.atDay(safeDay)
                    .atTime(start.toLocalTime())
                    .atZone(start.getZone());

            if (!candidate.isBefore(start) && candidate.isAfter(cursor.minusSeconds(1))) {
                return candidate;
            }
        }
        return null;
    }
}
