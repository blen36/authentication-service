package com.example.authenticationservice.service;

import com.example.authenticationservice.config.JwtProperties;
import com.example.authenticationservice.dto.TokenResponseDto;
import com.example.authenticationservice.entity.Credential;
import com.example.authenticationservice.entity.RefreshToken;
import com.example.authenticationservice.repository.RefreshTokenRepository;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
public class TokenService {
    private final JwtEncoder encoder;
    private final JwtProperties properties;
    private final RefreshTokenRepository refreshTokens;

    public TokenService(JwtEncoder encoder, JwtProperties properties, RefreshTokenRepository refreshTokens) {
        this.encoder = encoder;
        this.properties = properties;
        this.refreshTokens = refreshTokens;
    }

    // Called inside AuthService's transaction so refresh rotation is atomic.
    public TokenResponseDto issuePair(Credential credential) {
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        UUID refreshId = UUID.randomUUID();
        Instant refreshExpiry = now.plusSeconds(properties.refreshTtlSeconds());
        String access = encode(credential, "access", UUID.randomUUID(), now,
                now.plusSeconds(properties.accessTtlSeconds()));
        String refresh = encode(credential, "refresh", refreshId, now, refreshExpiry);
        refreshTokens.save(new RefreshToken(refreshId, credential, hash(refresh), refreshExpiry));
        return new TokenResponseDto(access, refresh, "Bearer", properties.accessTtlSeconds(),
                properties.refreshTtlSeconds());
    }

    private String encode(Credential credential, String type, UUID id, Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer()).audience(List.of(properties.audience()))
                .subject(credential.getUserId().toString()).id(id.toString())
                .issuedAt(issuedAt).notBefore(issuedAt).expiresAt(expiresAt)
                .claim("userId", credential.getUserId()).claim("role", credential.getRole().name())
                .claim("tokenType", type).build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).type("JWT").build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
