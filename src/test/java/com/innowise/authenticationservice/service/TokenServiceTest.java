package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.config.JwtProperties;
import com.innowise.authenticationservice.entity.Credential;
import com.innowise.authenticationservice.entity.RefreshToken;
import com.innowise.authenticationservice.entity.Role;
import com.innowise.authenticationservice.repository.RefreshTokenRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class TokenServiceTest {
    @Test void pairHasCorrectClaimsLifetimesAndOnlyRefreshHashIsStored() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAKey key = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey((RSAPrivateKey) pair.getPrivate()).keyIDFromThumbprint().build();
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        JwtDecoder decoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) pair.getPublic()).build();
        RefreshTokenRepository repository = mock(RefreshTokenRepository.class);
        var service = new TokenService(encoder,
                new JwtProperties("authentication-service", "java-advanced-api", 900, 604800, null, null),
                repository, key);
        var result = service.issuePair(new Credential(15L, "vlad", "hash", Role.USER));
        Jwt access = decoder.decode(result.accessToken());
        Jwt refresh = decoder.decode(result.refreshToken());
        assertThat(result.tokenType()).isEqualTo("Bearer");
        assertThat(result.expiresIn()).isEqualTo(900);
        assertThat(result.refreshExpiresIn()).isEqualTo(604800);
        assertThat(access.getHeaders().get("kid")).isEqualTo(key.getKeyID());
        assertThat(access.getSubject()).isEqualTo("15");
        assertThat(access.getClaimAsString("role")).isEqualTo("USER");
        assertThat(access.getClaimAsString("tokenType")).isEqualTo("access");
        assertThat(access.getClaimAsString("user_id")).isEqualTo("15");
        assertThat(access.getClaimAsString("iss")).isEqualTo("authentication-service");
        assertThat(access.getAudience()).containsExactly("java-advanced-api");
        assertThat(access.getExpiresAt()).isEqualTo(access.getIssuedAt().plusSeconds(900));
        assertThat(refresh.getClaimAsString("tokenType")).isEqualTo("refresh");
        assertThat(refresh.getExpiresAt()).isEqualTo(refresh.getIssuedAt().plusSeconds(604800));
        assertThat(access.getId()).isNotEqualTo(refresh.getId());
        var stored = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(stored.capture());
        assertThat(stored.getValue().getId()).isEqualTo(UUID.fromString(refresh.getId()));
        assertThat(stored.getValue().getTokenHash()).isEqualTo(TokenService.hash(result.refreshToken()));
        assertThat(stored.getValue().getTokenHash()).hasSize(64).isNotEqualTo(result.refreshToken());
        assertThat(stored.getValue().isConsumed()).isFalse();
    }

    @Test void storedFingerprintUsesSha256() {
        assertThat(TokenService.hash("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
