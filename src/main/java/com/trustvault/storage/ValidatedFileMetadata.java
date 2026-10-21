package com.trustvault.storage;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Objects;

/**
 * Immutable record representing file metadata and payload content validated against
 * TrustVault's security policies.
 *
 * <p>Contains the exact normalized attributes required by
 * {@link com.trustvault.entity.Document#setFileMetadata(java.util.UUID, String, String, Long, String, java.time.Instant)}
 * as well as the buffered bytes ready for persistence in {@link StorageService}.
 *
 * @param originalFilename sanitized basename of the original uploaded file (max 255 chars)
 * @param contentType      canonical validated MIME content type (max 100 chars)
 * @param size             exact byte length of the file payload (1 to 10,485,760 bytes)
 * @param checksum         64-character lowercase hexadecimal SHA-256 digest
 * @param content          in-memory byte payload of the validated file
 */
public record ValidatedFileMetadata(
        String originalFilename,
        String contentType,
        long size,
        String checksum,
        byte[] content
) {
    public ValidatedFileMetadata {
        Objects.requireNonNull(originalFilename, "Original filename must not be null");
        Objects.requireNonNull(contentType, "Content type must not be null");
        Objects.requireNonNull(checksum, "Checksum must not be null");
        Objects.requireNonNull(content, "Content bytes must not be null");
    }

    /**
     * Opens a new {@link InputStream} over the validated in-memory content bytes.
     *
     * @return a fresh {@link ByteArrayInputStream}
     */
    public InputStream openStream() {
        return new ByteArrayInputStream(content);
    }
}
