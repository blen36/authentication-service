package com.innowise.authenticationservice.config;

import com.innowise.authenticationservice.security.JwtSupport;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class JwtConfig {
    @Bean
    RSAPublicKey rsaPublicKey(JwtProperties properties) throws IOException {
        try (var input = properties.publicKey().getInputStream()) {
            RSAPublicKey key = RsaKeyConverters.x509().convert(input);
            if (key == null || key.getModulus().bitLength() < 2048) {
                throw new IllegalStateException("An RSA public key of at least 2048 bits is required");
            }
            return key;
        }
    }

    @Bean
    RSAKey signingKey(JwtProperties properties, RSAPublicKey publicKey) throws IOException, JOSEException {
        RSAPrivateKey privateKey;
        try (var input = properties.privateKey().getInputStream()) {
            privateKey = RsaKeyConverters.pkcs8().convert(input);
        }
        if (privateKey == null || !privateKey.getModulus().equals(publicKey.getModulus())) {
            throw new IllegalStateException("JWT private and public keys must form one RSA key pair");
        }
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyIDFromThumbprint().build();
    }

    @Bean
    JwtEncoder jwtEncoder(RSAKey signingKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(signingKey)));
    }

    @Bean("accessJwtDecoder")
    @Primary
    JwtDecoder accessJwtDecoder(JwtProperties properties, RSAPublicKey publicKey) {
        return decoder(properties, publicKey, "access");
    }

    @Bean("refreshJwtDecoder")
    JwtDecoder refreshJwtDecoder(JwtProperties properties, RSAPublicKey publicKey) {
        return decoder(properties, publicKey, "refresh");
    }

    private JwtDecoder decoder(JwtProperties properties, RSAPublicKey key, String type) {
        return JwtSupport.decoder(key, properties.issuer(), properties.audience(), type);
    }
}
