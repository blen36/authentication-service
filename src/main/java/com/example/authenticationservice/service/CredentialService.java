package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.*;
import com.example.authenticationservice.entity.*;
import com.example.authenticationservice.exception.CredentialConflictException;
import com.example.authenticationservice.repository.CredentialRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Locale;

@Service
public class CredentialService {
    private final CredentialRepository credentials;
    private final PasswordEncoder passwordEncoder;

    public CredentialService(CredentialRepository credentials, PasswordEncoder passwordEncoder) {
        this.credentials = credentials;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public CredentialResponseDto create(CredentialRequestDto request) {
        Credential credential = save(request, Role.USER);
        return new CredentialResponseDto(credential.getUserId(), credential.getLogin(), credential.getRole());
    }

    @Transactional
    public void bootstrapAdmin(CredentialRequestDto request) {
        String login = normalizeLogin(request.login());
        var existing = credentials.findByLogin(login);
        if (existing.isPresent()) {
            Credential credential = existing.get();
            if (credential.getUserId().equals(request.userId()) && credential.getRole() == Role.ADMIN) {
                return; // Restarting never resets an existing admin password.
            }
            throw new IllegalStateException("Bootstrap login is already assigned to another account");
        }
        save(request, Role.ADMIN);
    }

    private Credential save(CredentialRequestDto request, Role role) {
        String login = normalizeLogin(request.login());
        if (credentials.existsByLogin(login) || credentials.existsByUserId(request.userId())) {
            throw new CredentialConflictException("Login or userId already has credentials");
        }
        return credentials.saveAndFlush(new Credential(request.userId(), login,
                passwordEncoder.encode(request.password()), role));
    }

    public static String normalizeLogin(String login) {
        return login.trim().toLowerCase(Locale.ROOT);
    }
}
