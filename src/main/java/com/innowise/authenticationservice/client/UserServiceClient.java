package com.innowise.authenticationservice.client;

import com.innowise.authenticationservice.config.ProvisioningProperties;
import com.innowise.authenticationservice.dto.RegisterRequestDto;
import java.time.LocalDate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

@Component
public class UserServiceClient {
    private final RestClient client;

    public UserServiceClient(RestClient.Builder builder, @Value("${auth.user-service-url}") String baseUrl,
                             ProvisioningProperties provisioning) {
        client = builder.baseUrl(baseUrl).defaultHeader("X-Registration-Key", provisioning.key()).build();
    }

    public long create(RegisterRequestDto request) {
        var profile = new Profile(request.name(), request.surname(), request.birthDate(), request.email());
        try {
            CreatedUser created = client.post().uri("/api/users").contentType(MediaType.APPLICATION_JSON)
                    .body(profile).retrieve().body(CreatedUser.class);
            if (created == null || created.id() == null || created.id() <= 0) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "User Service returned no profile ID");
            }
            return created.id();
        } catch (HttpClientErrorException.Conflict ex) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Profile email already exists", ex);
        }
    }

    public void delete(long id) {
        client.delete().uri("/api/users/{id}", id).retrieve()
                .onStatus(status -> status.value() == 404, (request, response) -> { })
                .toBodilessEntity();
    }

    private record Profile(String name, String surname, LocalDate birthDate, String email) {}
    private record CreatedUser(Long id) {}
}
