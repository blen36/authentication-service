package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.LoginRequestDto;
import com.example.authenticationservice.dto.TokenResponseDto;
import com.example.authenticationservice.entity.RefreshToken;
import com.example.authenticationservice.repository.*;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.UUID;

@Service
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final CredentialRepository credentials;
    private final RefreshTokenRepository refreshTokens;
    private final JwtDecoder refreshDecoder;
    private final TokenService tokenService;

    public AuthService(AuthenticationManager authenticationManager, CredentialRepository credentials,
                       RefreshTokenRepository refreshTokens,
                       @Qualifier("refreshJwtDecoder") JwtDecoder refreshDecoder, TokenService tokenService) {
        this.authenticationManager = authenticationManager;
        this.credentials = credentials;
        this.refreshTokens = refreshTokens;
        this.refreshDecoder = refreshDecoder;
        this.tokenService = tokenService;
    }

    @Transactional
    public TokenResponseDto login(LoginRequestDto request) {
        String login = CredentialService.normalizeLogin(request.login());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(login, request.password()));
        var credential = credentials.findByLogin(login)
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        return tokenService.issuePair(credential);
    }

    @Transactional
    public TokenResponseDto refresh(String rawToken) {
        Jwt jwt = refreshDecoder.decode(rawToken);
        UUID id;
        try {
            id = UUID.fromString(jwt.getId());
        } catch (IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid refresh token");
        }
        RefreshToken stored = refreshTokens.findForUpdate(id)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));
        boolean hashMatches = MessageDigest.isEqual(
                stored.getTokenHash().getBytes(StandardCharsets.US_ASCII),
                TokenService.hash(rawToken).getBytes(StandardCharsets.US_ASCII));
        if (stored.isConsumed() || !stored.getExpiresAt().isAfter(Instant.now()) || !hashMatches
                || !stored.getCredential().getUserId().toString().equals(jwt.getSubject())) {
            throw new BadCredentialsException("Invalid refresh token");
        }
        stored.consume();
        return tokenService.issuePair(stored.getCredential());
    }
}
