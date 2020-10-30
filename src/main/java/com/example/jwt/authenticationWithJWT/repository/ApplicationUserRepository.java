package com.example.jwt.authenticationWithJWT.repository;

import com.example.jwt.authenticationWithJWT.entity.ApplicationUser;
import org.springframework.data.jpa.repository.JpaRepository;


public interface ApplicationUserRepository extends JpaRepository<ApplicationUser, Long> {
    ApplicationUser findByUsername(String username);
}
