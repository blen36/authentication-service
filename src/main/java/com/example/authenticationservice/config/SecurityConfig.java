package com.example.authenticationservice.config;

import com.example.authenticationservice.security.ProvisioningKeyFilter;
import com.example.authenticationservice.security.SecurityErrorWriter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean
    AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                               PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(encoder);
        return new ProviderManager(provider);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
            @Qualifier("accessJwtDecoder") JwtDecoder decoder,
            ProvisioningProperties provisioning, SecurityErrorWriter errors) throws Exception {
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("role");
        roles.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(roles);

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(rules -> rules
                        .requestMatchers(HttpMethod.GET, "/api/ping").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login",
                                "/api/v1/auth/refresh", "/api/v1/auth/credentials").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/validate").authenticated()
                        .anyRequest().denyAll())
                .exceptionHandling(errorsConfig -> errorsConfig
                        .authenticationEntryPoint((req, res, ex) -> errors.write(req, res,
                                HttpStatus.UNAUTHORIZED, "A valid access token is required"))
                        .accessDeniedHandler((req, res, ex) -> errors.write(req, res,
                                HttpStatus.FORBIDDEN, "Access denied")))
                .oauth2ResourceServer(resource -> resource
                        .jwt(jwt -> jwt.decoder(decoder).jwtAuthenticationConverter(converter))
                        .authenticationEntryPoint((req, res, ex) -> errors.write(req, res,
                                HttpStatus.UNAUTHORIZED, "Invalid or expired access token"))
                        .accessDeniedHandler((req, res, ex) -> errors.write(req, res,
                                HttpStatus.FORBIDDEN, "Access denied")))
                .addFilterBefore(new ProvisioningKeyFilter(provisioning, errors),
                        UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
