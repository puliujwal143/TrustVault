package com.trustvault.dto;

import com.trustvault.entity.Document;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

/**
 * View model representing a document row on the user's dashboard.
 *
 * Security Requirements:
 * - Completely decouples view rendering from JPA entities and lazy associations,
 *   strictly adhering to spring.jpa.open-in-view=false.
 * - Exposes only client-safe metadata: logical storageKey, title, description,
 *   owner username, permission indicators, and safe file metadata.
 * - NEVER exposes passwords, physical file-storage keys ({fileStorageKey}.bin),
 *   filesystem paths, internal checksums, or binary stream contents.
 */
public record DocumentItemViewModel(
        Long id,
        UUID storageKey,
        String title,
        String description,
        String ownerUsername,
        boolean isOwner,
        String permissionLabel,
        boolean hasFile,
        String fileOriginalName,
        String fileContentType,
        Long fileSize,
        String formattedFileSize,
        Instant createdAt,
        Instant updatedAt
) {
    /**
     * Constructs a safe DocumentItemViewModel from a Document entity and authenticated user context.
     *
     * @param doc             the Document entity
     * @param currentUsername the authenticated user viewing the dashboard
     * @param permissionLabel the resolved permission level ("OWNER", "EDIT", or "READ")
     * @return populated DocumentItemViewModel
     */
    public static DocumentItemViewModel from(Document doc, String currentUsername, String permissionLabel) {
        if (doc == null) {
            return null;
        }

        String ownerName = doc.getOwner() != null ? doc.getOwner().getUsername() : null;
        boolean owner = ownerName != null && ownerName.equalsIgnoreCase(currentUsername);
        String resolvedPermission = owner ? "OWNER" : (permissionLabel != null ? permissionLabel : "READ");

        boolean hasFile = doc.hasFile();
        Long size = hasFile ? doc.getFileSize() : null;

        return new DocumentItemViewModel(
                doc.getId(),
                doc.getStorageKey(),
                doc.getTitle(),
                doc.getDescription(),
                ownerName,
                owner,
                resolvedPermission,
                hasFile,
                hasFile ? doc.getFileOriginalName() : null,
                hasFile ? doc.getFileContentType() : null,
                size,
                formatFileSize(size),
                doc.getCreatedAt(),
                doc.getUpdatedAt()
        );
    }

    /**
     * Formats raw byte count into human-readable representation (e.g. "1.2 MB", "450 KB", "12 B").
     */
    public static String formatFileSize(Long bytes) {
        if (bytes == null || bytes < 0) {
            return null;
        }
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0);
        }
        return String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0));
    }
}
