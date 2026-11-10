package com.innowise.authenticationservice.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;

public record RegisterRequestDto(
        @NotBlank @Size(max = 100) String name,
        @NotBlank @Size(max = 100) String surname,
        @NotNull @Past LocalDate birthDate,
        @NotBlank @Email @Size(max = 320) String email,
        @JsonAlias("username") @NotBlank @Size(min = 3, max = 100)
        @Pattern(regexp = "[A-Za-z0-9._@+\\-]+") String login,
        @NotBlank @Size(min = 8, max = 72) String password
) {
    @AssertTrue(message = "Password must contain at most 72 UTF-8 bytes for BCrypt")
    public boolean isPasswordWithinBcryptLimit() {
        return password == null || password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
