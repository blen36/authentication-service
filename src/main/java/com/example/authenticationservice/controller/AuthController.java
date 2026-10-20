package com.example.authenticationservice.controller;

import com.example.authenticationservice.dto.CredentialRequestDto;
import com.example.authenticationservice.dto.CredentialResponseDto;
import com.example.authenticationservice.dto.LoginRequestDto;

import com.example.authenticationservice.service.AuthService;
import com.example.authenticationservice.service.CredentialService;

import jakarta.validation.Valid;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final CredentialService credentialService;
    private final AuthService authService;

    public AuthController(
            CredentialService credentialService,
            AuthService authService
    ) {
        this.credentialService = credentialService;
        this.authService = authService;
    }

    @PostMapping("/credentials")
    public ResponseEntity<CredentialResponseDto> createCredentials(
            @Valid @RequestBody CredentialRequestDto request,

            @RequestHeader(
                    name = "X-Registration-Key",
                    required = false
            )
            String registrationKey
    ) {
        CredentialResponseDto response =
                credentialService.create(request, registrationKey);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .cacheControl(CacheControl.noStore())
                .body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<CredentialResponseDto> login(
            @Valid @RequestBody LoginRequestDto request
    ) {
        return ResponseEntity
                .ok()
                .cacheControl(CacheControl.noStore())
                .body(authService.login(request));
    }
}