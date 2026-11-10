package com.innowise.authenticationservice.client;

import com.innowise.authenticationservice.config.ProvisioningProperties;
import com.innowise.authenticationservice.dto.RegisterRequestDto;
import java.time.LocalDate;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class UserServiceClientTest {
    @Test
    void sendsOnlyProfileFieldsAndAcceptsRepeatedDeletion() {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        String key = "test-registration-key-0123456789abcdef";
        var client = new UserServiceClient(builder, "http://profiles.test", new ProvisioningProperties(key));
        var request = new RegisterRequestDto("Ann", "Doe", LocalDate.of(2000, 1, 1),
                "ann@example.com", "ann", "TestPassword123!");
        String profile = """
                {"name":"Ann","surname":"Doe","birthDate":"2000-01-01","email":"ann@example.com"}
                """;
        server.expect(requestTo("http://profiles.test/api/users")).andExpect(method(HttpMethod.POST))
                .andExpect(header("X-Registration-Key", key)).andExpect(content().json(profile, JsonCompareMode.STRICT))
                .andRespond(withSuccess("{\"id\":12,\"name\":\"Ann\"}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("http://profiles.test/api/users/12")).andExpect(method(HttpMethod.DELETE))
                .andExpect(header("X-Registration-Key", key)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        assertThat(client.create(request)).isEqualTo(12L);
        client.delete(12L);
        server.verify();
    }
}
