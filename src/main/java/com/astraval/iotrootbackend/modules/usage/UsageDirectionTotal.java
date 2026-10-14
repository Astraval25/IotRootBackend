package com.astraval.iotrootbackend.modules.usage;

public record UsageDirectionTotal(
        UsageDirection direction,
        Long messageCount,
        Long payloadBytes,
        Long estimatedTotalBytes
) {
}
