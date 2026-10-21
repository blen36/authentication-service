package com.example.authenticationservice.security;

import com.example.authenticationservice.config.ProvisioningProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class ProvisioningKeyFilter extends OncePerRequestFilter {
    private static final RequestMatcher CREDENTIALS = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/api/v1/auth/credentials");
    private final byte[] expectedKey;
    private final SecurityErrorWriter errors;

    public ProvisioningKeyFilter(ProvisioningProperties properties, SecurityErrorWriter errors) {
        this.expectedKey = properties.key().getBytes(StandardCharsets.UTF_8);
        this.errors = errors;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !CREDENTIALS.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String supplied = request.getHeader("X-Registration-Key");
        if (supplied == null || !MessageDigest.isEqual(expectedKey,
                supplied.getBytes(StandardCharsets.UTF_8))) {
            errors.write(request, response, HttpStatus.UNAUTHORIZED,
                    "A valid registration key is required");
            return;
        }
        chain.doFilter(request, response);
    }
}
