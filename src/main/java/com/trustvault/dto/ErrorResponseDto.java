package com.trustvault.dto;

import java.time.Instant;
import java.util.List;

/**
 * Standard error response envelope for API exceptions.
 *
 * Prevents internal stack traces from leaking to clients while providing
 * clear and actionable diagnostic messages.
 *
 * @param timestamp UTC timestamp of the error
 * @param status    HTTP status code
 * @param error     HTTP status description
 * @param message   User-friendly error message
 * @param path      Request path that generated the error
 * @param details   Optional list of validation errors or details
 */
public record ErrorResponseDto(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        List<String> details
) {
    public static ErrorResponseDto of(int status, String error, String message, String path) {
        return new ErrorResponseDto(Instant.now(), status, error, message, path, List.of());
    }

    public static ErrorResponseDto of(int status, String error, String message, String path, List<String> details) {
        return new ErrorResponseDto(Instant.now(), status, error, message, path, details);
    }
}
