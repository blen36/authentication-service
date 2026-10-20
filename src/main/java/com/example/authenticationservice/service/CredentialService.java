package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.CredentialRequestDto;
import com.example.authenticationservice.dto.CredentialResponseDto;
import com.example.authenticationservice.entity.Credential;
import com.example.authenticationservice.entity.Role;
import com.example.authenticationservice.exception.DuplicateCredentialsException;
import com.example.authenticationservice.repository.CredentialRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

@Service
public class CredentialService {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final byte[] registrationKey;

    public CredentialService(
            CredentialRepository credentialRepository,
            PasswordEncoder passwordEncoder,
            @Value("${auth.registration-key}") String registrationKey
    ) {
        if (registrationKey.isBlank() || registrationKey.length() < 32) {
            throw new IllegalStateException(
                    "AUTH_REGISTRATION_KEY must contain at least 32 characters"
            );
        }

        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.registrationKey =
                registrationKey.getBytes(StandardCharsets.UTF_8);
    }

    @Transactional
    public CredentialResponseDto create(
            CredentialRequestDto request,
            String suppliedKey
    ) {
        checkRegistrationKey(suppliedKey);

        Credential credential = saveCredential(
                request,
                Role.USER
        );

        return toResponse(credential);
    }

    @Transactional
    public void bootstrapAdmin(CredentialRequestDto request) {
        String login = normalizeLogin(request.login());

        var existing = credentialRepository.findByLogin(login);

        if (existing.isPresent()) {
            Credential credential = existing.get();

            boolean sameAdmin =
                    credential.getUserId().equals(request.userId())
                            && credential.getRole() == Role.ADMIN;

            if (sameAdmin) {
                return;
            }

            throw new IllegalStateException(
                    "Bootstrap login is already assigned to another account"
            );
        }

        saveCredential(request, Role.ADMIN);
    }

    private Credential saveCredential(
            CredentialRequestDto request,
            Role role
    ) {
        String login = normalizeLogin(request.login());

        if (credentialRepository.existsByLogin(login)) {
            throw new DuplicateCredentialsException(
                    "Login is already taken"
            );
        }

        if (credentialRepository.existsByUserId(request.userId())) {
            throw new DuplicateCredentialsException(
                    "User already has credentials"
            );
        }

        String passwordHash =
                passwordEncoder.encode(request.password());

        Credential credential = new Credential(
                request.userId(),
                login,
                passwordHash,
                role
        );

        return credentialRepository.saveAndFlush(credential);
    }

    private void checkRegistrationKey(String suppliedKey) {
        if (suppliedKey == null) {
            throw new BadCredentialsException(
                    "Invalid registration key"
            );
        }

        byte[] suppliedBytes =
                suppliedKey.getBytes(StandardCharsets.UTF_8);

        if (!MessageDigest.isEqual(registrationKey, suppliedBytes)) {
            throw new BadCredentialsException(
                    "Invalid registration key"
            );
        }
    }

    private CredentialResponseDto toResponse(
            Credential credential
    ) {
        return new CredentialResponseDto(
                credential.getUserId(),
                credential.getLogin(),
                credential.getRole()
        );
    }

    public static String normalizeLogin(String login) {
        return login.trim().toLowerCase(Locale.ROOT);
    }
}