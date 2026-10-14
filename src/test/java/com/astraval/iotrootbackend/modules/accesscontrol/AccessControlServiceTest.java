package com.astraval.iotrootbackend.modules.accesscontrol;

import com.astraval.iotrootbackend.modules.accesscontrol.dto.AccessControlRequest;
import com.astraval.iotrootbackend.modules.accesscontrol.dto.AccessControlResponse;
import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.device.DeviceService;
import com.astraval.iotrootbackend.modules.user.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccessControlServiceTest {

    private AccessControlService service;

    @BeforeEach
    void setUp() {
        AccessControlRepository repository = mock(AccessControlRepository.class);
        DeviceService deviceService = mock(DeviceService.class);

        User user = new User();
        user.setUserId(4L);
        Device device = new Device();
        device.setId(12L);
        device.setUser(user);

        when(deviceService.resolveUser("4")).thenReturn(user);
        when(deviceService.resolveDevice(12L, 4L)).thenReturn(device);
        when(repository.save(any(AccessControl.class))).thenAnswer(invocation -> invocation.getArgument(0));
        service = new AccessControlService(repository, deviceService);
    }

    @Test
    void createsStoreRulesInReservedTopLevelNamespace() {
        AccessControlRequest request = request("status", AccessControlRequest.TopicType.STORE);

        AccessControlResponse response = service.addRule(12L, request, "4");

        assertEquals("/iot/store/4/status", response.getTopic());
        assertEquals("STORE", response.getTopicType());
    }

    @Test
    void normalStoreNamedPathDoesNotBecomeAStoreRule() {
        AccessControlRequest request = request("store/status", AccessControlRequest.TopicType.STANDARD);

        AccessControlResponse response = service.addRule(12L, request, "4");

        assertEquals("/iot/4/store/status", response.getTopic());
        assertEquals("STANDARD", response.getTopicType());
    }

    private AccessControlRequest request(String topic, AccessControlRequest.TopicType topicType) {
        AccessControlRequest request = new AccessControlRequest();
        request.setTopic(topic);
        request.setTopicType(topicType);
        request.setPermission(AccessControl.Permission.publish);
        return request;
    }
}
