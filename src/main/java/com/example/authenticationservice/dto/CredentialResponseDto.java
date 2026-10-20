package com.example.authenticationservice.dto;

import com.example.authenticationservice.entity.Role;

public record CredentialResponseDto(
        Long userId,
        String login,
        Role role
) {
}