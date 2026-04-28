package com.astraval.iotrootbackend.modules.user.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class UserDto {
    private String userName;

    private String email;

    private String password;
}
