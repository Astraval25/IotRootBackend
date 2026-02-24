package com.astraval.iotrootbackend.common.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends ApplicationException {

    public ResourceNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}
