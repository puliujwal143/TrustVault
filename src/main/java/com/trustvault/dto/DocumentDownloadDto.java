package com.trustvault.dto;

import org.springframework.core.io.Resource;

import java.util.Objects;

/**
 * Data transfer object encapsulating a validated document file download payload.
 *
 * <p>Security Considerations:
 * <ul>
 *   <li>Contains the verified {@link Resource} representation of the file.</li>
 *   <li>Suppresses physical file storage keys ({fileStorageKey}.bin), storage directories,
 *       and filesystem paths.</li>
 *   <li>Holds safe presentation metadata: sanitized original filename, MIME content type,
 *       and exact byte size.</li>
 * </ul>
 *
 * @param resource         the readable Spring Resource containing file bytes
 * @param originalFilename the original sanitized client filename
 * @param contentType      the validated MIME content type
 * @param fileSize         the exact byte size of the payload
 */
public record DocumentDownloadDto(
        Resource resource,
        String originalFilename,
        String contentType,
        long fileSize
) {
    public DocumentDownloadDto {
        Objects.requireNonNull(resource, "Resource must not be null");
        Objects.requireNonNull(originalFilename, "Original filename must not be null");
        Objects.requireNonNull(contentType, "Content type must not be null");
    }
}
