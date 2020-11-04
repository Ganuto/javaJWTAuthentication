package com.example.jwt.authenticationWithJWT.http;

import com.example.jwt.authenticationWithJWT.entity.ApplicationUser;
import com.example.jwt.authenticationWithJWT.repository.ApplicationUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final ApplicationUserRepository applicationUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping(value = "/record")
    public void singUp(
            @RequestBody ApplicationUser user
    ) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        this.applicationUserRepository.save(user);
    }
}
