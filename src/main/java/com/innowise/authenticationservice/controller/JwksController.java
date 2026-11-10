package com.innowise.authenticationservice.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {
    private final JWKSet publicKeys;

    public JwksController(RSAKey signingKey) {
        publicKeys = new JWKSet(signingKey.toPublicJWK());
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> publicKeys() {
        return publicKeys.toJSONObject();
    }
}
