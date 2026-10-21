package com.example.authenticationservice.security;

import com.example.authenticationservice.repository.CredentialRepository;
import com.example.authenticationservice.service.CredentialService;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CredentialUserDetailsService implements UserDetailsService {
    private final CredentialRepository credentials;

    public CredentialUserDetailsService(CredentialRepository credentials) {
        this.credentials = credentials;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        var credential = credentials.findByLogin(CredentialService.normalizeLogin(username))
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));
        return User.withUsername(credential.getLogin()).password(credential.getPasswordHash())
                .roles(credential.getRole().name()).build();
    }
}
