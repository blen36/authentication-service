package com.innowise.authenticationservice.dto;

import com.innowise.authenticationservice.entity.Role;

public record CredentialResponseDto(Long userId, String login, Role role) {}
