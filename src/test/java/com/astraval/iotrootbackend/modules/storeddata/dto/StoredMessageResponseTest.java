package com.astraval.iotrootbackend.modules.storeddata.dto;

import com.astraval.iotrootbackend.modules.device.Device;
import com.astraval.iotrootbackend.modules.storeddata.StoredMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class StoredMessageResponseTest {

    @Test
    void convertsStoredJsonTreeToPlainJsonValues() throws Exception {
        Device device = new Device();
        device.setId(10L);

        StoredMessage message = new StoredMessage();
        message.setDevice(device);
        message.setPayload(new ObjectMapper().readTree("""
                {
                  "value": 1,
                  "active": true,
                  "readings": [12.5, 13.75],
                  "metadata": {"location": "office"}
                }
                """));

        StoredMessageResponse response = StoredMessageResponse.from(message);

        Map<?, ?> payload = assertInstanceOf(Map.class, response.getPayload());
        assertEquals(1L, payload.get("value"));
        assertEquals(true, payload.get("active"));
        assertEquals(List.of(new BigDecimal("12.5"), new BigDecimal("13.75")), payload.get("readings"));
        assertEquals(Map.of("location", "office"), payload.get("metadata"));
    }
}
