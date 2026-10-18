package com.trustvault.dto;

import java.time.Instant;

/**
 * Data Transfer Object for health status responses.
 *
 * Immutable Java 21 record representing the application health status.
 *
 * @param status    Service status ("UP", "DOWN", etc.)
 * @param service   Application identifier
 * @param timestamp UTC timestamp when the health check was evaluated
 */
public record HealthResponseDto(
        String status,
        String service,
        Instant timestamp
) {
    public static HealthResponseDto up() {
        return new HealthResponseDto("UP", "TrustVault", Instant.now());
    }
}
