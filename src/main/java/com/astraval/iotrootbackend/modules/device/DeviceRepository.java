package com.astraval.iotrootbackend.modules.device;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface DeviceRepository extends JpaRepository<Device, Long> {

    List<Device> findByUserUserId(Long userId);

    Optional<Device> findByIdAndUserUserId(Long id, Long userId);

    Optional<Device> findByClientId(String clientId);
}
