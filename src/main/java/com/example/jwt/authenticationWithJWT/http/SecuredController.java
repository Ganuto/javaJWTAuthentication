package com.example.jwt.authenticationWithJWT.http;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/secure", consumes = MediaType.APPLICATION_JSON_VALUE)
public class SecuredController {

    @GetMapping
    public ResponseEntity<String> reachSecureEndpoint() {
        return new ResponseEntity<String>("If your are reading this you reached a secure endpoint", HttpStatus.OK);
    }
}
