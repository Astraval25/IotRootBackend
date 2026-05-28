package com.astraval.iotrootbackend.modules.screen;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ScreenRepository extends JpaRepository<Screen, Long> {
    List<Screen> findByUserUserIdOrderByUpdatedAtDesc(Long userId);
    Optional<Screen> findByIdAndUserUserId(Long id, Long userId);
}

