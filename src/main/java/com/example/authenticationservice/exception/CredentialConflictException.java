package com.example.authenticationservice.exception;

public class CredentialConflictException extends RuntimeException {
    public CredentialConflictException(String message) { super(message); }
}
