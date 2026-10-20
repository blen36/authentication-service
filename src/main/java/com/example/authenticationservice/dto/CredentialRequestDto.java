package com.example.authenticationservice.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.nio.charset.StandardCharsets;

public record CredentialRequestDto(

        @NotNull
        @Positive
        Long userId,

        @NotBlank
        @Size(min = 3, max = 100)
        @Pattern(
                regexp = "[A-Za-z0-9._@+\\-]+",
                message = "Login contains unsupported characters"
        )
        String login,

        @NotBlank
        @Size(min = 8, max = 72)
        String password

) {

    @AssertTrue(
            message = "Password must contain at most 72 UTF-8 bytes"
    )
    public boolean isPasswordWithinBcryptLimit() {
        return password == null
                || password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}