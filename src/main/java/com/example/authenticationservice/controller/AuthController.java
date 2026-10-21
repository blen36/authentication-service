package com.example.authenticationservice.controller;

import com.example.authenticationservice.dto.*;
import com.example.authenticationservice.service.*;
import jakarta.validation.Valid;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final CredentialService credentialService;
    private final AuthService authService;

    public AuthController(CredentialService credentialService, AuthService authService) {
        this.credentialService = credentialService;
        this.authService = authService;
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
        Number userId = jwt.getClaim("userId");
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new TokenValidationResponseDto(
                true, userId.longValue(), jwt.getClaimAsString("role"), jwt.getExpiresAt()));
    }
}
