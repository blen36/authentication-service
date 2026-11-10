package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.client.UserServiceClient;
import com.innowise.authenticationservice.dto.CredentialRequestDto;
import com.innowise.authenticationservice.dto.CredentialResponseDto;
import com.innowise.authenticationservice.dto.RegisterRequestDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class RegistrationService {
    private static final Logger log = LoggerFactory.getLogger(RegistrationService.class);
    private final UserServiceClient users;
    private final CredentialService credentials;

    public RegistrationService(UserServiceClient users, CredentialService credentials) {
        this.users = users;
        this.credentials = credentials;
    }

    public CredentialResponseDto register(RegisterRequestDto request) {
        long id = users.create(request);
        try {
            // The proxied method owns the local transaction, including its commit.
            return credentials.create(new CredentialRequestDto(id, request.login(), request.password()));
        } catch (RuntimeException failure) {
            try {
                users.delete(id);
            } catch (RuntimeException rollbackFailure) {
                failure.addSuppressed(rollbackFailure);
                log.error("Registration rollback failed for profile {}", id);
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Profile rollback failed", failure);
            }
            throw failure;
        }
    }
}
