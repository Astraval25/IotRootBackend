package com.astraval.iotrootbackend.modules.accesscontrol;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AccessControlRepository extends JpaRepository<AccessControl, Long> {

    List<AccessControl> findByDeviceIdAndDeviceUserUserId(Long deviceId, Long userId);

    Optional<AccessControl> findByIdAndDeviceIdAndDeviceUserUserId(Long id, Long deviceId, Long userId);
}
