package com.innowise.authenticationservice.security;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

public final class JwtSupport {
    private JwtSupport() {}

    public static JwtDecoder decoder(RSAPublicKey publicKey, String issuer,
                                     String audience, String expectedType) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256).build();
        OAuth2TokenValidator<Jwt> claims = jwt -> {
            try {
                Object userId = jwt.getClaim("user_id");
                String subject = jwt.getSubject();
                String role = jwt.getClaimAsString("role");
                if (userId instanceof Number && subject != null
                        && subject.equals(userId.toString()) && Long.parseLong(subject) > 0
                        && ("ADMIN".equals(role) || "USER".equals(role))
                        && jwt.getIssuedAt() != null && jwt.getExpiresAt() != null
                        && jwt.getExpiresAt().isAfter(jwt.getIssuedAt())
                        && jwt.getId() != null && !jwt.getId().isBlank()
                        && jwt.getAudience() != null && jwt.getAudience().contains(audience)
                        && expectedType.equals(jwt.getClaimAsString("tokenType"))) {
                    return OAuth2TokenValidatorResult.success();
                }
            } catch (RuntimeException ignored) {
                // Invalid claims must result in 401, not a server error.
            }
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Invalid token claims or token type", null));
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ZERO), new JwtIssuerValidator(issuer), claims));
        return decoder;
    }
}
