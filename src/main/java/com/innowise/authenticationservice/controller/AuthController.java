package com.innowise.authenticationservice.controller;

import com.innowise.authenticationservice.dto.CredentialRequestDto;
import com.innowise.authenticationservice.dto.CredentialResponseDto;
import com.innowise.authenticationservice.dto.LoginRequestDto;
import com.innowise.authenticationservice.dto.RefreshRequestDto;
import com.innowise.authenticationservice.dto.RegisterRequestDto;
import com.innowise.authenticationservice.dto.TokenResponseDto;
import com.innowise.authenticationservice.dto.TokenValidationResponseDto;
import com.innowise.authenticationservice.service.AuthService;
import com.innowise.authenticationservice.service.CredentialService;
import com.innowise.authenticationservice.service.RegistrationService;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final CredentialService credentialService;
    private final AuthService authService;
    private final RegistrationService registration;

    public AuthController(CredentialService credentialService, AuthService authService, RegistrationService registration) {
        this.registration = registration;
        this.credentialService = credentialService;
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<CredentialResponseDto> register(@Valid @RequestBody RegisterRequestDto request) {
        return ResponseEntity.status(HttpStatus.CREATED).cacheControl(CacheControl.noStore())
                .body(registration.register(request));
    }

    @PostMapping("/credentials")
    public ResponseEntity<CredentialResponseDto> createCredentials(@Valid @RequestBody CredentialRequestDto request) {
        return ResponseEntity.status(HttpStatus.CREATED).cacheControl(CacheControl.noStore())
                .body(credentialService.create(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache").body(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponseDto> refresh(@Valid @RequestBody RefreshRequestDto request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache").body(authService.refresh(request.refreshToken()));
    }

    @GetMapping("/validate")
    public ResponseEntity<TokenValidationResponseDto> validate(@AuthenticationPrincipal Jwt jwt) {
        Number userId = jwt.getClaim("user_id");
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new TokenValidationResponseDto(
                true, userId.longValue(), jwt.getClaimAsString("role"), jwt.getExpiresAt()));
    }
}
