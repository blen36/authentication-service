package com.example.authenticationservice.dto;

public record TokenResponseDto(String accessToken, String refreshToken, String tokenType,
                            long expiresIn, long refreshExpiresIn) {}
