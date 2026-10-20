package com.example.authenticationservice.security;

import com.example.authenticationservice.entity.Credential;
import com.example.authenticationservice.repository.CredentialRepository;
import com.example.authenticationservice.service.CredentialService;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CredentialUserDetailsService
        implements UserDetailsService {

    private final CredentialRepository credentialRepository;

    public CredentialUserDetailsService(
            CredentialRepository credentialRepository
    ) {
        this.credentialRepository = credentialRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {

        String login =
                CredentialService.normalizeLogin(username);

        Credential credential = credentialRepository
                .findByLogin(login)
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                "Invalid credentials"
                        )
                );

        return User
                .withUsername(credential.getLogin())
                .password(credential.getPasswordHash())
                .roles(credential.getRole().name())
                .build();
    }
}