package com.example.jwt.authenticationWithJWT.security;

import com.example.jwt.authenticationWithJWT.entity.ApplicationUser;
import com.example.jwt.authenticationWithJWT.entity.TokenResponseBody;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Key;
import java.util.ArrayList;
import java.util.Date;

import static com.example.jwt.authenticationWithJWT.configs.SecurityConstants.EXPIRATION_TIME;
import static com.example.jwt.authenticationWithJWT.configs.SecurityConstants.KEY;

@RequiredArgsConstructor
public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException {
        try {
            ApplicationUser applicationUser = this.objectMapper.readValue(request.getInputStream(), ApplicationUser.class);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword(), new ArrayList<>());

            return this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (IOException exception) {
            throw new RuntimeException(exception);
        }

    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException {
        Date expirationDate = new Date(System.currentTimeMillis() + EXPIRATION_TIME);
        Key key = Keys.hmacShaKeyFor(KEY.getBytes());
        Claims claims = Jwts.claims().setSubject(((User) authResult.getPrincipal()).getUsername());
        String token = Jwts.builder().setClaims(claims).signWith(key, SignatureAlgorithm.HS512).setExpiration(expirationDate).compact();

        PrintWriter responseBody = response.getWriter();
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        TokenResponseBody tokenResponseBody = new TokenResponseBody(token, "A SER IMPLEMENTADO");
        responseBody.print(this.objectMapper.writeValueAsString(tokenResponseBody));
        responseBody.flush();
    }
}
