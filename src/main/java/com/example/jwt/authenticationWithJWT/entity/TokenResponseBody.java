package com.example.jwt.authenticationWithJWT.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import static com.example.jwt.authenticationWithJWT.configs.SecurityConstants.EXPIRATION_TIME;

@Getter
@Setter
@RequiredArgsConstructor
public class TokenResponseBody {
    private final String token_type = "bearer";
    private final String access_token;
    private final Long expires_in = EXPIRATION_TIME / 60000;
    private final String refresh_token;
}
