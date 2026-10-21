package com.example.authenticationservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.AssertTrue;
import java.nio.charset.StandardCharsets;

public record LoginRequestDto(
        @NotBlank @Size(max = 100) String login,
        @NotBlank @Size(max = 72) String password
) {
    @AssertTrue(message = "Password must contain at most 72 UTF-8 bytes for BCrypt")
    public boolean isPasswordWithinBcryptLimit() {
        return password == null || password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
