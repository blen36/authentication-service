package com.example.authenticationservice;

import com.example.authenticationservice.entity.Role;
import com.example.authenticationservice.repository.*;
import com.example.authenticationservice.service.*;
import com.example.authenticationservice.dto.CredentialRequestDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = "spring.profiles.active=test")
@AutoConfigureMockMvc
class AuthenticationServiceApplicationTests {
    private static final String REGISTRATION_KEY = "test-only-registration-key-at-least-32-characters";
    private static final String PASSWORD = "TestPassword123!";
    private static final Path KEY_DIRECTORY = createTestKeys();

    @DynamicPropertySource
    static void keyProperties(DynamicPropertyRegistry registry) {
        registry.add("auth.jwt.private-key", () -> KEY_DIRECTORY.resolve("private.pem").toUri().toString());
        registry.add("auth.jwt.public-key", () -> KEY_DIRECTORY.resolve("public.pem").toUri().toString());
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired CredentialRepository credentials;
    @Autowired RefreshTokenRepository refreshTokens;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtEncoder encoder;
    @Autowired AuthService authService;
    @Autowired CredentialService credentialService;

    @BeforeEach
    void cleanDatabase() {
        refreshTokens.deleteAll();
        credentials.deleteAll();
    }

    @Test
    void pingIsPublic() throws Exception {
        mvc.perform(get("/api/ping")).andExpect(status().isOk());
    }

    @Test
    void registrationRequiresInternalKey() throws Exception {
        mvc.perform(post("/api/v1/auth/credentials").contentType(MediaType.APPLICATION_JSON)
                .content(registration(15L, "vlad"))).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
        assertThat(credentials.count()).isZero();
    }

    @Test
    void invalidRegistrationKeyIsRejected() throws Exception {
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", "wrong")
                .contentType(MediaType.APPLICATION_JSON).content(registration(15L, "vlad")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void encodedCredentialPathCannotBypassInternalKey() throws Exception {
        mvc.perform(post(java.net.URI.create("/api/v1/auth/cred%65ntials"))
                .contentType(MediaType.APPLICATION_JSON).content(registration(15L, "vlad")))
                .andExpect(status().is4xxClientError());
        assertThat(credentials.count()).isZero();
    }

    @Test
    void credentialsAreNormalizedHashedAndNeverReturned() throws Exception {
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", REGISTRATION_KEY)
                .contentType(MediaType.APPLICATION_JSON).content(registration(15L, "Vlad")))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.login").value("vlad"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
        var credential = credentials.findByLogin("vlad").orElseThrow();
        assertThat(credential.getCreatedAt()).isNotNull();
        assertThat(credential.getUpdatedAt()).isNotNull();
        assertThat(credential.getPasswordHash()).startsWith("$2").isNotEqualTo(PASSWORD);
        assertThat(passwords.matches(PASSWORD, credential.getPasswordHash())).isTrue();
    }

    @Test
    void samePasswordGetsDifferentSalts() throws Exception {
        register(15L, "first");
        register(16L, "second");
        assertThat(credentials.findByLogin("first").orElseThrow().getPasswordHash())
                .isNotEqualTo(credentials.findByLogin("second").orElseThrow().getPasswordHash());
    }

    @Test
    void duplicateLoginIgnoringCaseReturns409() throws Exception {
        register(15L, "vlad");
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", REGISTRATION_KEY)
                .contentType(MediaType.APPLICATION_JSON).content(registration(16L, "VLAD")))
                .andExpect(status().isConflict());
    }

    @Test
    void duplicateUserIdReturns409() throws Exception {
        register(15L, "vlad");
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", REGISTRATION_KEY)
                .contentType(MediaType.APPLICATION_JSON).content(registration(15L, "another")))
                .andExpect(status().isConflict());
    }

    @Test
    void weakPasswordReturns400() throws Exception {
        String body = mapper.writeValueAsString(Map.of("userId", 15, "login", "vlad", "password", "123"));
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", REGISTRATION_KEY)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isBadRequest());
    }

    @Test
    void bcryptByteLimitIsValidatedForUnicode() throws Exception {
        String body = mapper.writeValueAsString(Map.of("userId", 15, "login", "vlad", "password", "я".repeat(40)));
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", REGISTRATION_KEY)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isBadRequest());
    }

    @Test
    void roleCannotBeElevatedInRegistrationBody() throws Exception {
        String body = mapper.writeValueAsString(Map.of("userId", 15, "login", "vlad",
                "password", PASSWORD, "role", "ADMIN"));
        // Unknown fields may be ignored, but the service always assigns USER.
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", REGISTRATION_KEY)
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void loginIssuesTwoDifferentTokensWithNoStore() throws Exception {
        register(15L, "vlad");
        JsonNode tokens = login("VLAD", PASSWORD);
        assertThat(tokens.path("accessToken").asText()).isNotBlank()
                .isNotEqualTo(tokens.path("refreshToken").asText());
        var stored = refreshTokens.findAll().getFirst();
        assertThat(stored.getTokenHash()).hasSize(64)
                .isEqualTo(TokenService.hash(tokens.path("refreshToken").asText()));
    }

    @Test
    void wrongPasswordReturns401() throws Exception {
        register(15L, "vlad");
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("login", "vlad", "password", "WrongPassword!"))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void unknownLoginReturns401() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("login", "missing", "password", PASSWORD))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validAccessTokenReturnsIdentity() throws Exception {
        register(15L, "vlad");
        String token = login("vlad", PASSWORD).path("accessToken").asText();
        mvc.perform(get("/api/v1/auth/validate").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(15)).andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void missingAccessTokenReturns401() throws Exception {
        mvc.perform(get("/api/v1/auth/validate")).andExpect(status().isUnauthorized());
    }

    @Test
    void refreshCannotBeUsedAsAccessToken() throws Exception {
        register(15L, "vlad");
        String token = login("vlad", PASSWORD).path("refreshToken").asText();
        mvc.perform(get("/api/v1/auth/validate").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void accessCannotBeUsedAsRefreshToken() throws Exception {
        register(15L, "vlad");
        String token = login("vlad", PASSWORD).path("accessToken").asText();
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("refreshToken", token))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshRotatesAndRejectsReplay() throws Exception {
        register(15L, "vlad");
        JsonNode original = login("vlad", PASSWORD);
        String oldRefresh = original.path("refreshToken").asText();
        String response = mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("refreshToken", oldRefresh))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonNode replacement = mapper.readTree(response);
        assertThat(replacement.path("refreshToken").asText()).isNotEqualTo(oldRefresh);
        assertThat(replacement.path("accessToken").asText()).isNotEqualTo(original.path("accessToken").asText());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("refreshToken", oldRefresh))))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("refreshToken", replacement.path("refreshToken").asText()))))
                .andExpect(status().isOk());
    }

    @Test
    void concurrentRefreshHasExactlyOneWinner() throws Exception {
        register(15L, "vlad");
        String raw = login("vlad", PASSWORD).path("refreshToken").asText();
        CountDownLatch start = new CountDownLatch(1);
        Callable<Boolean> task = () -> {
            start.await();
            try { authService.refresh(raw); return true; }
            catch (AuthenticationException ex) { return false; }
        };
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<Boolean> first = executor.submit(task);
            Future<Boolean> second = executor.submit(task);
            start.countDown();
            assertThat(List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
    }

    @Test
    void expiredAccessReturns401() throws Exception {
        String token = signedToken("access", "authentication-service", "java-advanced-api", Instant.now().minusSeconds(120));
        mvc.perform(get("/api/v1/auth/validate").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongIssuerReturns401() throws Exception {
        String token = signedToken("access", "other-issuer", "java-advanced-api", Instant.now().plusSeconds(300));
        mvc.perform(get("/api/v1/auth/validate").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongAudienceReturns401() throws Exception {
        String token = signedToken("access", "authentication-service", "another-api", Instant.now().plusSeconds(300));
        mvc.perform(get("/api/v1/auth/validate").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedSignatureReturns401() throws Exception {
        register(15L, "vlad");
        String token = login("vlad", PASSWORD).path("accessToken").asText();
        int signatureStart = token.lastIndexOf('.') + 1;
        char changed = token.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, signatureStart) + changed + token.substring(signatureStart + 1);
        mvc.perform(get("/api/v1/auth/validate").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void malformedJsonReturns400() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content("{broken"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void bootstrapCreatesAdminWithoutResettingPassword() throws Exception {
        credentialService.bootstrapAdmin(new CredentialRequestDto(1L, "admin", PASSWORD));
        String previousHash = credentials.findByLogin("admin").orElseThrow().getPasswordHash();
        credentialService.bootstrapAdmin(new CredentialRequestDto(1L, "admin", "AnotherPassword!"));
        assertThat(credentials.findByLogin("admin").orElseThrow().getPasswordHash()).isEqualTo(previousHash);
        assertThat(credentials.findByLogin("admin").orElseThrow().getRole()).isEqualTo(Role.ADMIN);
        String access = login("admin", PASSWORD).path("accessToken").asText();
        mvc.perform(get("/api/v1/auth/validate").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk()).andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    void malformedRefreshTokenReturns401() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("refreshToken", "not-a-jwt"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void emptyRefreshTokenReturns400() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void expiredRefreshTokenReturns401() throws Exception {
        String token = signedToken("refresh", "authentication-service", "java-advanced-api",
                Instant.now().minusSeconds(120));
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("refreshToken", token))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signedButUnstoredRefreshTokenReturns401() throws Exception {
        String token = signedToken("refresh", "authentication-service", "java-advanced-api",
                Instant.now().plusSeconds(300));
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("refreshToken", token))))
                .andExpect(status().isUnauthorized());
        assertThat(refreshTokens.count()).isZero();
    }

    private void register(Long userId, String login) throws Exception {
        mvc.perform(post("/api/v1/auth/credentials").header("X-Registration-Key", REGISTRATION_KEY)
                .contentType(MediaType.APPLICATION_JSON).content(registration(userId, login)))
                .andExpect(status().isCreated());
    }

    private String registration(Long userId, String login) {
        return mapper.writeValueAsString(Map.of("userId", userId, "login", login, "password", PASSWORD));
    }

    private JsonNode login(String login, String password) throws Exception {
        String result = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("login", login, "password", password))))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andReturn().getResponse().getContentAsString();
        return mapper.readTree(result);
    }

    private String signedToken(String type, String issuer, String audience, Instant expiry) {
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience))
                .subject("15").id(UUID.randomUUID().toString()).issuedAt(Instant.now().minusSeconds(600))
                .notBefore(Instant.now().minusSeconds(600)).expiresAt(expiry)
                .claim("userId", 15L).claim("role", "USER").claim("tokenType", type).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256)
                .type("JWT").build(), claims)).getTokenValue();
    }

    private static Path createTestKeys() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            Path directory = Files.createTempDirectory("auth-test-keys-");
            writePem(directory.resolve("private.pem"), "PRIVATE KEY", pair.getPrivate().getEncoded());
            writePem(directory.resolve("public.pem"), "PUBLIC KEY", pair.getPublic().getEncoded());
            return directory;
        } catch (Exception ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }

    private static void writePem(Path path, String type, byte[] bytes) throws Exception {
        Files.writeString(path, "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes)
                + "\n-----END " + type + "-----\n", StandardCharsets.US_ASCII);
        path.toFile().deleteOnExit();
    }
}
