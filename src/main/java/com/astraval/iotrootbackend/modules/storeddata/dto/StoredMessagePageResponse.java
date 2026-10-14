package com.astraval.iotrootbackend.modules.storeddata.dto;

import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
public class StoredMessagePageResponse {
    private List<StoredMessageResponse> content;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
    private Instant from;
    private Instant to;
}
