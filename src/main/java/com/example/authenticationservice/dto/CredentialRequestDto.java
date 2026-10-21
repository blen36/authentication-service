package com.example.authenticationservice.dto;

import jakarta.validation.constraints.*;
import java.nio.charset.StandardCharsets;

public record CredentialRequestDto(
        @NotNull @Positive Long userId,
        @NotBlank @Size(min = 3, max = 100)
        @Pattern(regexp = "[A-Za-z0-9._@+\\-]+", message = "Use letters, digits, dots, _, @, + or -") String login,
        @NotBlank @Size(min = 8, max = 72) String password
) {
    @AssertTrue(message = "Password must contain at most 72 UTF-8 bytes for BCrypt")
    public boolean isPasswordWithinBcryptLimit() {
        return password == null || password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
