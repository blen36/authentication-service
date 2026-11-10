package com.innowise.authenticationservice.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.jwt")
public record JwtProperties(
        @NotBlank String issuer,
        @NotBlank String audience,
        @Min(1) long accessTtlSeconds,
        @Min(1) long refreshTtlSeconds,
        @NotNull Resource privateKey,
        @NotNull Resource publicKey
) {}
