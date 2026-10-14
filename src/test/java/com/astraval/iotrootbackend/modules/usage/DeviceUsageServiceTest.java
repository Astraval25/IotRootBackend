package com.astraval.iotrootbackend.modules.usage;

import com.astraval.iotrootbackend.modules.device.DeviceRepository;
import com.astraval.iotrootbackend.modules.device.DeviceStatusPushService;
import com.astraval.iotrootbackend.modules.storeddata.StoredMessageRepository;
import com.astraval.iotrootbackend.modules.storeddata.StoredMessageService;
import com.astraval.iotrootbackend.modules.usage.dto.AccountUsageOverviewResponse;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class DeviceUsageServiceTest {

    @Test
    void accountOverviewCombinesTrafficStoredDataAndDeviceCount() {
        DeviceRepository deviceRepository = mock(DeviceRepository.class);
        DeviceUsageBucketRepository bucketRepository = mock(DeviceUsageBucketRepository.class);
        StoredMessageRepository storedRepository = mock(StoredMessageRepository.class);
        DeviceUsageService service = new DeviceUsageService(
                deviceRepository,
                bucketRepository,
                mock(DeviceStatusPushService.class),
                mock(StoredMessageService.class),
                storedRepository);
        Instant from = Instant.parse("2026-10-14T09:00:00Z");
        Instant to = Instant.parse("2026-10-14T10:00:00Z");

        DeviceUsageBucket inbound = bucket(UsageDirection.INBOUND, 3, 120, 180);
        DeviceUsageBucket outbound = bucket(UsageDirection.OUTBOUND, 5, 240, 320);
        when(bucketRepository.findByUserAndRange(4L, from, to)).thenReturn(List.of(inbound, outbound));
        when(deviceRepository.countByUserUserId(4L)).thenReturn(2L);
        when(storedRepository.countByUserUserIdAndReceivedAtBetween(4L, from, to)).thenReturn(3L);
        when(storedRepository.sumPayloadBytesByUserAndRange(4L, from, to)).thenReturn(96L);

        AccountUsageOverviewResponse result = service.getAccountUsageOverview(4L, from, to);

        assertEquals(2, result.getDeviceCount());
        assertEquals(3, result.getInboundMessages());
        assertEquals(5, result.getOutboundMessages());
        assertEquals(8, result.getTotalTransactions());
        assertEquals(180, result.getInboundEstimatedTotalBytes());
        assertEquals(320, result.getOutboundEstimatedTotalBytes());
        assertEquals(3, result.getStoredMessageCount());
        assertEquals(96, result.getStoredPayloadBytes());
    }

    @Test
    void unfilteredAccountOverviewReturnsAllRecordedUsage() {
        DeviceRepository deviceRepository = mock(DeviceRepository.class);
        DeviceUsageBucketRepository bucketRepository = mock(DeviceUsageBucketRepository.class);
        StoredMessageRepository storedRepository = mock(StoredMessageRepository.class);
        DeviceUsageService service = new DeviceUsageService(
                deviceRepository,
                bucketRepository,
                mock(DeviceStatusPushService.class),
                mock(StoredMessageService.class),
                storedRepository);

        when(bucketRepository.sumAllByUser(4L)).thenReturn(List.of(
                new UsageDirectionTotal(UsageDirection.INBOUND, 30L, 1_200L, 1_800L),
                new UsageDirectionTotal(UsageDirection.OUTBOUND, 50L, 2_400L, 3_200L)));
        when(deviceRepository.countByUserUserId(4L)).thenReturn(2L);
        when(storedRepository.countByUserUserId(4L)).thenReturn(12L);
        when(storedRepository.sumPayloadBytesByUser(4L)).thenReturn(960L);

        AccountUsageOverviewResponse result = service.getAccountUsageOverview(4L, null, null);

        assertEquals(30, result.getInboundMessages());
        assertEquals(50, result.getOutboundMessages());
        assertEquals(80, result.getTotalTransactions());
        assertEquals(1_800, result.getInboundEstimatedTotalBytes());
        assertEquals(3_200, result.getOutboundEstimatedTotalBytes());
        assertEquals(12, result.getStoredMessageCount());
        assertEquals(960, result.getStoredPayloadBytes());
        verify(bucketRepository, never()).findByUserAndRange(anyLong(), any(), any());
    }

    private DeviceUsageBucket bucket(UsageDirection direction, long messages, long payloadBytes, long totalBytes) {
        DeviceUsageBucket bucket = new DeviceUsageBucket();
        bucket.setDirection(direction);
        bucket.setMessageCount(messages);
        bucket.setPayloadBytes(payloadBytes);
        bucket.setEstimatedTotalBytes(totalBytes);
        return bucket;
    }
}
