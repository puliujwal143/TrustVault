package com.trustvault.exception;

/**
 * Exception thrown when a requested resource does not exist or when an unauthorized caller
 * attempts to discover a private resource they have no permission to access.
 *
 * Mapped to HTTP 404 Not Found to neutralize IDOR / BOLA enumeration attacks.
 */
public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
