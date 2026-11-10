package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.repository.RefreshTokenRepository;
import java.time.Instant;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class RefreshTokenCleanup {
    private final RefreshTokenRepository tokens;

    public RefreshTokenCleanup(RefreshTokenRepository tokens) {
        this.tokens = tokens;
    }

    @Scheduled(fixedDelayString = "${auth.refresh-cleanup-delay:PT1H}", initialDelayString = "${auth.refresh-cleanup-delay:PT1H}")
    @Transactional
    public void deleteUnusable() {
        tokens.deleteUnusable(Instant.now());
    }
}
