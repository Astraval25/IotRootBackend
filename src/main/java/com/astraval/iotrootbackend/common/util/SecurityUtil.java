package com.astraval.iotrootbackend.common.util;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityUtil {

    public String getCurrentSub() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
