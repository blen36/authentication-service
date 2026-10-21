package com.example.authenticationservice.service;

import com.example.authenticationservice.dto.CredentialRequestDto;
import com.example.authenticationservice.entity.Credential;
import com.example.authenticationservice.entity.Role;
import com.example.authenticationservice.exception.CredentialConflictException;
import com.example.authenticationservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.Optional;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialServiceTest {
    @Mock CredentialRepository credentials;
    @Mock PasswordEncoder passwords;
    CredentialService service;
    final CredentialRequestDto request = new CredentialRequestDto(15L, "  Vlad  ", "Password123!");

    @BeforeEach void setUp() { service = new CredentialService(credentials, passwords); }

    @Test void createStoresHashAndAlwaysAssignsUserRole() {
        when(passwords.encode(request.password())).thenReturn("bcrypt-hash");
        when(credentials.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        var response = service.create(request);
        var captor = ArgumentCaptor.forClass(Credential.class);
        verify(credentials).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getPasswordHash()).isEqualTo("bcrypt-hash");
        assertThat(response.userId()).isEqualTo(15L);
        assertThat(response.login()).isEqualTo("vlad");
        assertThat(response.role()).isEqualTo(Role.USER);
    }

    @Test void duplicateLoginDoesNotEncodeOrSave() {
        when(credentials.existsByLogin("vlad")).thenReturn(true);
        assertThatThrownBy(() -> service.create(request)).isInstanceOf(CredentialConflictException.class);
        verifyNoInteractions(passwords);
        verify(credentials, never()).saveAndFlush(any());
    }

    @Test void duplicateUserIdDoesNotEncodeOrSave() {
        when(credentials.existsByUserId(15L)).thenReturn(true);
        assertThatThrownBy(() -> service.create(request)).isInstanceOf(CredentialConflictException.class);
        verifyNoInteractions(passwords);
        verify(credentials, never()).saveAndFlush(any());
    }

    @Test void bootstrapCreatesAdmin() {
        when(passwords.encode(request.password())).thenReturn("admin-hash");
        when(credentials.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        service.bootstrapAdmin(request);
        var captor = ArgumentCaptor.forClass(Credential.class);
        verify(credentials).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getRole()).isEqualTo(Role.ADMIN);
    }

    @Test void existingAdminPasswordIsNeverReset() {
        when(credentials.findByLogin("vlad")).thenReturn(Optional.of(
                new Credential(15L, "vlad", "old-hash", Role.ADMIN)));
        service.bootstrapAdmin(request);
        verifyNoInteractions(passwords);
        verify(credentials, never()).saveAndFlush(any());
    }

    @Test void bootstrapCannotPromoteExistingUser() {
        when(credentials.findByLogin("vlad")).thenReturn(Optional.of(
                new Credential(15L, "vlad", "hash", Role.USER)));
        assertThatThrownBy(() -> service.bootstrapAdmin(request)).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(passwords);
    }

    @Test void bootstrapRejectsAdminAssignedToDifferentUser() {
        when(credentials.findByLogin("vlad")).thenReturn(Optional.of(
                new Credential(99L, "vlad", "hash", Role.ADMIN)));
        assertThatThrownBy(() -> service.bootstrapAdmin(request)).isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(passwords);
    }
}
