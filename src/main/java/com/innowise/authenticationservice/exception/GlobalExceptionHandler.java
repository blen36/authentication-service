package com.innowise.authenticationservice.exception;

import com.innowise.authenticationservice.dto.ErrorResponseDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestClientException;
import org.springframework.web.server.ResponseStatusException;

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

    @ExceptionHandler(ServletException.class)
    ResponseEntity<ErrorResponseDto> mvcError(ServletException exception, HttpServletRequest request) throws Exception {
        if (exception instanceof ErrorResponse mvc) {
            HttpStatus status = HttpStatus.valueOf(mvc.getStatusCode().value());
            var response = error(status, status.getReasonPhrase(), request, Map.of());
            return ResponseEntity.status(status).headers(response.getHeaders()).headers(mvc.getHeaders()).body(response.getBody());
        }
        throw exception;
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ErrorResponseDto> registrationFailure(ResponseStatusException ex, HttpServletRequest request) {
        return error(HttpStatus.valueOf(ex.getStatusCode().value()), ex.getReason(), request, Map.of());
    }

    @ExceptionHandler(RestClientException.class)
    ResponseEntity<ErrorResponseDto> downstreamFailure(RestClientException ex, HttpServletRequest request) {
        return error(HttpStatus.BAD_GATEWAY, "User Service request failed", request, Map.of());
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
