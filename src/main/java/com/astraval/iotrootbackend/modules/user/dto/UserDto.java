package com.astraval.iotrootbackend.modules.user.dto;

import java.time.LocalDateTime;
import java.util.List;


import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class UserDto {
    private String userName;

    private String email;

    private String password;
}
