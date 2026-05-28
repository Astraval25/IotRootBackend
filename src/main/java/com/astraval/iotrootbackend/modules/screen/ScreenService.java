package com.astraval.iotrootbackend.modules.screen;

import com.astraval.iotrootbackend.common.exception.ResourceNotFoundException;
import com.astraval.iotrootbackend.modules.device.DeviceService;
import com.astraval.iotrootbackend.modules.screen.dto.ScreenRequest;
import com.astraval.iotrootbackend.modules.screen.dto.ScreenResponse;
import com.astraval.iotrootbackend.modules.user.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class ScreenService {

    private final ScreenRepository screenRepository;
    private final DeviceService deviceService;

    public ScreenService(ScreenRepository screenRepository, DeviceService deviceService) {
        this.screenRepository = screenRepository;
        this.deviceService = deviceService;
    }

    @Transactional(readOnly = true)
    public List<ScreenResponse> getScreens(String sub) {
        Long userId = resolveUser(sub).getUserId();
        return screenRepository.findByUserUserIdOrderByUpdatedAtDesc(userId)
                .stream().map(ScreenResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public ScreenResponse getScreen(Long id, String sub) {
        Long userId = resolveUser(sub).getUserId();
        return ScreenResponse.from(resolveScreen(id, userId));
    }

    @Transactional
    public ScreenResponse createScreen(ScreenRequest req, String sub) {
        User user = resolveUser(sub);
        Screen screen = new Screen();
        screen.setUser(user);
        applyRequest(screen, req, user.getUserId());
        return ScreenResponse.from(screenRepository.save(screen));
    }

    @Transactional
    public ScreenResponse updateScreen(Long id, ScreenRequest req, String sub) {
        User user = resolveUser(sub);
        Screen screen = resolveScreen(id, user.getUserId());
        applyRequest(screen, req, user.getUserId());
        return ScreenResponse.from(screenRepository.save(screen));
    }

    @Transactional
    public void deleteScreen(Long id, String sub) {
        Long userId = resolveUser(sub).getUserId();
        screenRepository.delete(resolveScreen(id, userId));
    }

    public Screen resolveScreen(Long id, Long userId) {
        return screenRepository.findByIdAndUserUserId(id, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Screen not found"));
    }

    private User resolveUser(String sub) {
        return deviceService.resolveUser(sub);
    }

    private void applyRequest(Screen screen, ScreenRequest req, Long userId) {
        screen.setName(req.getName().trim());
        screen.setTriggerTopic(buildTopic(userId, req.getTriggerTopic()));
        screen.setTargetTopic(buildTopic(userId, req.getTargetTopic()));
        screen.setActionType(req.getActionType());
        screen.setPayload(req.getPayload());
        screen.setIsActive(req.getActive() == null ? true : req.getActive());
    }

    private String buildTopic(Long userId, String userTopic) {
        return "/iot/" + userId + "/" + userTopic;
    }
}

