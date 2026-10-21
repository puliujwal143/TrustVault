package com.trustvault.dto;

import com.trustvault.entity.Document;

import java.time.Instant;
import java.util.UUID;

/**
 * Data transfer object representing document metadata responses.
 *
 * <p>Prevents direct exposure of JPA entity internals and lazy proxies
 * in HTTP controller responses.
 *
 * <p>Security Considerations:
 * <ul>
 *   <li>Exposes logical {@code storageKey} required for client document referencing.</li>
 *   <li>NEVER exposes physical {@code fileStorageKey}, storage filesystem paths,
 *       or raw binary contents.</li>
 *   <li>Exposes safe client-facing file metadata: {@code hasFile}, {@code fileOriginalName},
 *       {@code fileContentType}, {@code fileSize}, and {@code fileUploadedAt}.</li>
 *   <li>For documents without attached files, {@code hasFile} is {@code false} and all file
 *       metadata fields are {@code null}.</li>
 * </ul>
 */
public record DocumentResponseDto(
        Long id,
        UUID storageKey,
        String title,
        String description,
        String ownerUsername,
        Instant createdAt,
        Instant updatedAt,
        boolean hasFile,
        String fileOriginalName,
        String fileContentType,
        Long fileSize,
        Instant fileUploadedAt
) {
    /**
     * Backward-compatible constructor for documents without attached files.
     */
    public DocumentResponseDto(
            Long id,
            UUID storageKey,
            String title,
            String description,
            String ownerUsername,
            Instant createdAt,
            Instant updatedAt
    ) {
        this(id, storageKey, title, description, ownerUsername, createdAt, updatedAt, false, null, null, null, null);
    }

    /**
     * Maps a {@link Document} entity into a client-safe {@link DocumentResponseDto}.
     *
     * <p>When the document has an associated file ({@code document.hasFile() == true}),
     * safe file metadata fields are populated. When no file is attached, {@code hasFile}
     * is {@code false} and all file metadata fields are {@code null}.
     *
     * @param document the document entity
     * @return a populated response DTO, or null if document is null
     */
    public static DocumentResponseDto from(Document document) {
        if (document == null) {
            return null;
        }

        boolean hasFile = document.hasFile();
        return new DocumentResponseDto(
                document.getId(),
                document.getStorageKey(),
                document.getTitle(),
                document.getDescription(),
                document.getOwner() != null ? document.getOwner().getUsername() : null,
                document.getCreatedAt(),
                document.getUpdatedAt(),
                hasFile,
                hasFile ? document.getFileOriginalName() : null,
                hasFile ? document.getFileContentType() : null,
                hasFile ? document.getFileSize() : null,
                hasFile ? document.getFileUploadedAt() : null
        );
    }
}
