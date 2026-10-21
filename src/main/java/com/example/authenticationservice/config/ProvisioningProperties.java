package com.example.authenticationservice.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "auth.provisioning")
public record ProvisioningProperties(@NotBlank @Size(min = 32) String key) {}
