package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.CredentialResponseDto;
import com.example.authenticationservice.dto.LoginRequestDto;
import com.example.authenticationservice.entity.Credential;
import com.example.authenticationservice.repository.CredentialRepository;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final CredentialRepository credentialRepository;

    public AuthService(
            AuthenticationManager authenticationManager,
            CredentialRepository credentialRepository
    ) {
        this.authenticationManager = authenticationManager;
        this.credentialRepository = credentialRepository;
    }

    @Transactional(readOnly = true)
    public CredentialResponseDto login(LoginRequestDto request) {

        String login =
                CredentialService.normalizeLogin(request.login());

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        login,
                        request.password()
                )
        );

        Credential credential = credentialRepository
                .findByLogin(login)
                .orElseThrow(() ->
                        new BadCredentialsException(
                                "Invalid credentials"
                        )
                );

        return new CredentialResponseDto(
                credential.getUserId(),
                credential.getLogin(),
                credential.getRole()
        );
    }
}