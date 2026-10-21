package com.example.authenticationservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshRequestDto(@NotBlank @Size(max = 8192) String refreshToken) {}
