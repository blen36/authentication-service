package com.innowise.authenticationservice.dto;

import java.time.Instant;

public record TokenValidationResponseDto(boolean valid, Long userId, String role, Instant expiresAt) {}
