package com.astraval.iotrootbackend.modules.storeddata;

import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.*;

class StoredMessageServiceTest {

    private StoredMessageRepository repository;
    private StoredMessageService service;
    private Device device;

    @BeforeEach
    void setUp() {
        repository = mock(StoredMessageRepository.class);
        service = new StoredMessageService(repository, new ObjectMapper());

        User user = new User();
        user.setUserId(4L);
        device = new Device();
        device.setId(12L);
        device.setClientId("client-12");
        device.setUser(user);
    }

    @Test
    void storesJsonFromOwnedStoreTopicOnPublish() {
        service.storePublishedMessageIfApplicable(Map.of(
                "topic", "/iot/store/4/sensors/bedroom",
                "payload", "{\"temperature\":27.4}",
                "qos", 1,
                "retain", false
        ), "on_publish", device);

        ArgumentCaptor<StoredMessage> captor = ArgumentCaptor.forClass(StoredMessage.class);
        verify(repository).save(captor.capture());
        StoredMessage message = captor.getValue();
        assertEquals(4L, message.getUser().getUserId());
        assertEquals(12L, message.getDevice().getId());
        assertEquals("sensors/bedroom", message.getStorePath());
        assertEquals(27.4, message.getPayload().get("temperature").doubleValue());
        assertEquals(1, message.getQos());
        assertFalse(message.getRetained());
    }

    @Test
    void ignoresDeliveriesWrongOwnersAndInvalidJson() {
        service.storePublishedMessageIfApplicable(Map.of(
                "topic", "/iot/store/4/value", "payload", "{\"ok\":true}"
        ), "on_deliver", device);
        service.storePublishedMessageIfApplicable(Map.of(
                "topic", "/iot/store/9/value", "payload", "{\"ok\":true}"
        ), "on_publish", device);
        service.storePublishedMessageIfApplicable(Map.of(
                "topic", "/iot/store/4/value", "payload", "not-json"
        ), "on_publish", device);
        service.storePublishedMessageIfApplicable(Map.of(
                "topic", "/iot/4/store/value", "payload", "{\"ok\":true}"
        ), "on_publish", device);

        verifyNoInteractions(repository);
    }
}
