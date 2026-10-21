package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.*;
import com.example.authenticationservice.entity.*;
import com.example.authenticationservice.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.*;
import org.springframework.security.oauth2.jwt.*;
import java.time.Instant;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {
    @Mock AuthenticationManager authentication;
    @Mock CredentialRepository credentials;
    @Mock RefreshTokenRepository refreshTokens;
    @Mock JwtDecoder decoder;
    @Mock TokenService tokens;
    AuthService service;
    final Credential credential = new Credential(15L, "vlad", "hash", Role.USER);
    final String raw = "test-refresh-token";
    final UUID id = UUID.randomUUID();
    final TokenResponseDto pair = new TokenResponseDto("access", "refresh", "Bearer", 900, 604800);

    @BeforeEach void setUp() {
        service = new AuthService(authentication, credentials, refreshTokens, decoder, tokens);
    }

    @Test void loginNormalizesNameAndIssuesTokensAfterAuthentication() {
        when(credentials.findByLogin("vlad")).thenReturn(Optional.of(credential));
        when(tokens.issuePair(credential)).thenReturn(pair);
        assertThat(service.login(new LoginRequestDto(" VLAD ", "Password123!"))).isSameAs(pair);
        var order = inOrder(authentication, credentials, tokens);
        order.verify(authentication).authenticate(argThat(a -> a.getName().equals("vlad")
                && a.getCredentials().equals("Password123!")));
        order.verify(credentials).findByLogin("vlad");
        order.verify(tokens).issuePair(credential);
    }

    @Test void wrongPasswordCannotIssueTokens() {
        when(authentication.authenticate(any())).thenThrow(new BadCredentialsException("Invalid"));
        assertThatThrownBy(() -> service.login(new LoginRequestDto("vlad", "wrong")))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(credentials, refreshTokens, tokens);
    }

    @Test void accountDisappearingAfterAuthenticationCannotIssueTokens() {
        assertThatThrownBy(() -> service.login(new LoginRequestDto("vlad", "password")))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(tokens);
    }

    @Test void refreshConsumesStoredTokenBeforeIssuingReplacement() {
        RefreshToken stored = stored(credential, TokenService.hash(raw), Instant.now().plusSeconds(300));
        arrangeRefresh(stored);
        when(tokens.issuePair(credential)).thenAnswer(invocation -> {
            assertThat(stored.isConsumed()).isTrue();
            return pair;
        });
        assertThat(service.refresh(raw)).isSameAs(pair);
    }

    @Test void consumedRefreshIsRejected() {
        RefreshToken stored = stored(credential, TokenService.hash(raw), Instant.now().plusSeconds(300));
        stored.consume();
        arrangeRefresh(stored);
        assertRejected();
    }

    @Test void expiredDatabaseRecordIsRejected() {
        arrangeRefresh(stored(credential, TokenService.hash(raw), Instant.now().minusSeconds(1)));
        assertRejected();
    }

    @Test void wrongStoredHashIsRejected() {
        arrangeRefresh(stored(credential, TokenService.hash("other"), Instant.now().plusSeconds(300)));
        assertRejected();
    }

    @Test void recordOwnedByAnotherUserIsRejected() {
        arrangeRefresh(stored(new Credential(99L, "other", "hash", Role.USER),
                TokenService.hash(raw), Instant.now().plusSeconds(300)));
        assertRejected();
    }

    @Test void missingStoredRefreshIsRejected() {
        when(decoder.decode(raw)).thenReturn(jwt(id.toString()));
        assertRejected();
    }

    @Test void invalidRefreshSignatureNeverTouchesDatabase() {
        when(decoder.decode(raw)).thenThrow(new BadJwtException("Invalid signature"));
        assertThatThrownBy(() -> service.refresh(raw)).isInstanceOf(JwtException.class);
        verifyNoInteractions(refreshTokens, tokens);
    }

    @Test void invalidRefreshIdNeverTouchesDatabase() {
        when(decoder.decode(raw)).thenReturn(jwt("not-a-uuid"));
        assertRejected();
        verifyNoInteractions(refreshTokens);
    }

    private void arrangeRefresh(RefreshToken stored) {
        when(decoder.decode(raw)).thenReturn(jwt(id.toString()));
        when(refreshTokens.findForUpdate(id)).thenReturn(Optional.of(stored));
    }
    private RefreshToken stored(Credential owner, String hash, Instant expiry) {
        return new RefreshToken(id, owner, hash, expiry);
    }
    private Jwt jwt(String tokenId) {
        return Jwt.withTokenValue(raw).header("alg", "RS256").subject("15").claim("jti", tokenId).build();
    }
    private void assertRejected() {
        assertThatThrownBy(() -> service.refresh(raw)).isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(tokens);
    }
}
