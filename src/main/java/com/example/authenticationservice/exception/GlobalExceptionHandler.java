package com.example.authenticationservice.exception;

import com.example.authenticationservice.dto.ErrorResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler({AuthenticationException.class, JwtException.class})
    ResponseEntity<ErrorResponseDto> unauthorized(Exception ex, HttpServletRequest request) {
        return error(HttpStatus.UNAUTHORIZED, "Invalid credentials or token", request, Map.of());
    }

    @ExceptionHandler(AccessDeniedException.class)
    ResponseEntity<ErrorResponseDto> forbidden(Exception ex, HttpServletRequest request) {
        return error(HttpStatus.FORBIDDEN, "Access denied", request, Map.of());
    }

    @ExceptionHandler({CredentialConflictException.class, DataIntegrityViolationException.class})
    ResponseEntity<ErrorResponseDto> conflict(Exception ex, HttpServletRequest request) {
        return error(HttpStatus.CONFLICT, "Login or userId already has credentials", request, Map.of());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ErrorResponseDto> invalidDto(MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> fields = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(e -> fields.putIfAbsent(e.getField(), e.getDefaultMessage()));
        return error(HttpStatus.BAD_REQUEST, "Request validation failed", request, fields);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ErrorResponseDto> invalidJson(Exception ex, HttpServletRequest request) {
        return error(HttpStatus.BAD_REQUEST, "Malformed JSON or invalid field type", request, Map.of());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ErrorResponseDto> wrongMethod(Exception ex, HttpServletRequest request) {
        return error(HttpStatus.METHOD_NOT_ALLOWED, "HTTP method is not supported", request, Map.of());
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorResponseDto> unexpected(Exception ex, HttpServletRequest request) {
        // Do not log request bodies: they can contain passwords or tokens.
        log.error("Unhandled error: {} on {}", ex.getClass().getSimpleName(), request.getRequestURI());
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected server error", request, Map.of());
    }

    private ResponseEntity<ErrorResponseDto> error(HttpStatus status, String message,
                                          HttpServletRequest request, Map<String, String> fields) {
        var builder = ResponseEntity.status(status).cacheControl(CacheControl.noStore());
        if (status == HttpStatus.UNAUTHORIZED) builder.header(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        return builder.body(new ErrorResponseDto(Instant.now(), status.value(), status.getReasonPhrase(),
                message, request.getRequestURI(), fields));
    }
}
