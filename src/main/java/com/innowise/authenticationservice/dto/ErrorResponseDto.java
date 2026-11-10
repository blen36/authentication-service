package com.innowise.authenticationservice.dto;

import java.time.Instant;
import java.util.Map;

public record ErrorResponseDto(Instant timestamp, int status, String error, String message,
                       String path, Map<String, String> fieldErrors) {}
