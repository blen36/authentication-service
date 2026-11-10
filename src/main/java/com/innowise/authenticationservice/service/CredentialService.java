package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.dto.CredentialRequestDto;
import com.innowise.authenticationservice.dto.CredentialResponseDto;
import com.innowise.authenticationservice.entity.Credential;
import com.innowise.authenticationservice.entity.Role;
import com.innowise.authenticationservice.exception.CredentialConflictException;
import com.innowise.authenticationservice.mapper.CredentialMapper;
import com.innowise.authenticationservice.repository.CredentialRepository;
import java.util.Locale;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CredentialService {
    private final CredentialRepository credentials;
    private final CredentialMapper mapper;
    private final PasswordEncoder passwordEncoder;

    public CredentialService(CredentialRepository credentials, PasswordEncoder passwordEncoder, CredentialMapper mapper) {
        this.mapper = mapper;
        this.credentials = credentials;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public CredentialResponseDto create(CredentialRequestDto request) {
        Credential credential = save(request, Role.USER);
        return mapper.toDto(credential);
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
