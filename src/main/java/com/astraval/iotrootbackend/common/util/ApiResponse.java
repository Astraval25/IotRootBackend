package com.astraval.iotrootbackend.common.util;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse<T> {
    private boolean status; // true if operation is successful
    private int code; // 200 - ok, 201 Created, 202 Accepted, 203 updated, 204 deleted.
    private String message; // human-readable message
    private T data; // actual response object (generic)

}
