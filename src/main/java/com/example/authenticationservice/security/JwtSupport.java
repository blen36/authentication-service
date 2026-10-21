package com.example.authenticationservice.security;

import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

public final class JwtSupport {
    private JwtSupport() {}

    public static RSAPublicKey readPublicKey(Resource resource) throws IOException {
        try (var input = resource.getInputStream()) {
            RSAPublicKey key = RsaKeyConverters.x509().convert(input);
            if (key == null || key.getModulus().bitLength() < 2048) {
                throw new IllegalStateException("An RSA public key of at least 2048 bits is required");
            }
            return key;
        }
    }

    public static JwtDecoder decoder(RSAPublicKey publicKey, String issuer,
                                     String audience, String expectedType) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256).build();
        OAuth2TokenValidator<Jwt> claims = jwt -> {
            try {
                Object userId = jwt.getClaim("userId");
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
