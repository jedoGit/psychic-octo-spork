package com.psychic.octo.spork.restServer.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDate;
import java.util.List;

@Getter
@AllArgsConstructor
public class UserInfoResponse {
    private final Long id;
    private final String username;
    private final String email;
    private final boolean accountNonLocked;
    private final boolean accountNonExpired;
    private final boolean credentialsNonExpired;
    private final boolean enabled;
    private final LocalDate credentialsExpiryDate;
    private final LocalDate accountExpiryDate;
    private final boolean isTwoFactorEnabled;
    private final List<String> roles;

}

