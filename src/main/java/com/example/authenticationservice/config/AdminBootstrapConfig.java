package com.example.authenticationservice.config;

import com.example.authenticationservice.dto.CredentialRequestDto;
import com.example.authenticationservice.service.CredentialService;

import jakarta.validation.Validator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(
        name = "auth.bootstrap.enabled",
        havingValue = "true"
)
public class AdminBootstrapConfig {

    @Bean
    public ApplicationRunner bootstrapAdmin(
            CredentialService credentialService,
            Validator validator,

            @Value("${AUTH_BOOTSTRAP_USER_ID}")
            Long userId,

            @Value("${AUTH_BOOTSTRAP_LOGIN}")
            String login,

            @Value("${AUTH_BOOTSTRAP_PASSWORD}")
            String password
    ) {
        return args -> {
            CredentialRequestDto request =
                    new CredentialRequestDto(
                            userId,
                            login,
                            password
                    );

            if (!validator.validate(request).isEmpty()) {
                throw new IllegalStateException(
                        "Invalid admin bootstrap settings"
                );
            }

            credentialService.bootstrapAdmin(request);
        };
    }
}