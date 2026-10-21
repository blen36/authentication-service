package com.example.authenticationservice.exception;

public class DuplicateCredentialsException extends RuntimeException {

    public DuplicateCredentialsException(String message) {
        super(message);
    }
}