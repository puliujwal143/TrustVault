package com.trustvault.dto;

import com.trustvault.entity.Document;

import java.time.Instant;
import java.util.UUID;

/**
 * Data transfer object representing document metadata responses.
 *
 * Prevents direct exposure of JPA entity internals and lazy proxies
 * in future HTTP controller responses.
 */
public record DocumentResponseDto(
        Long id,
        UUID storageKey,
        String title,
        String description,
        String ownerUsername,
        Instant createdAt,
        Instant updatedAt
) {
    public static DocumentResponseDto from(Document document) {
        return new DocumentResponseDto(
                document.getId(),
                document.getStorageKey(),
                document.getTitle(),
                document.getDescription(),
                document.getOwner().getUsername(),
                document.getCreatedAt(),
                document.getUpdatedAt()
        );
    }
}
