package com.astraval.iotrootbackend.modules.schedule;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ScheduleRepository extends JpaRepository<Schedule, Long> {
    List<Schedule> findByUserUserIdOrderByUpdatedAtDesc(Long userId);
    Optional<Schedule> findByIdAndUserUserId(Long id, Long userId);
}

