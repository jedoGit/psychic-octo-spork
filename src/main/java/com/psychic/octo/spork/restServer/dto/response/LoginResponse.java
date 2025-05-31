package com.psychic.octo.spork.restServer.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class LoginResponse {
    private final String username;
    private final List<String> roles;
    private final String jwtToken;
}

