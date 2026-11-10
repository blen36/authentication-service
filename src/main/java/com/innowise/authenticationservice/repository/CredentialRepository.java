package com.innowise.authenticationservice.repository;

import com.innowise.authenticationservice.entity.Credential;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CredentialRepository extends JpaRepository<Credential, Long> {
    Optional<Credential> findByLogin(String login);
    boolean existsByLogin(String login);
    boolean existsByUserId(Long userId);
}
