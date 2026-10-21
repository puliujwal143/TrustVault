package com.trustvault.storage;

/**
 * Exception thrown when uploaded file content, signature, size, filename, or container
 * metadata fails strict security validation.
 *
 * <p>Extends {@link IllegalArgumentException} so that existing global exception handlers
 * automatically map it to HTTP 400 Bad Request with a clean, client-safe error response.
 */
public class FileValidationException extends IllegalArgumentException {

    public FileValidationException(String message) {
        super(message);
    }

    public FileValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
