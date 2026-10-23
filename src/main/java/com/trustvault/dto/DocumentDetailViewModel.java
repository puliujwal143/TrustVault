package com.trustvault.dto;

import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

/**
 * Safe view model representing complete document details for the details view.
 *
 * Security Requirements:
 * - Decouples view rendering from JPA entities and lazy associations,
 *   strictly adhering to spring.jpa.open-in-view=false.
 * - Exposes only client-safe metadata: ID, title, description, owner username,
 *   caller's permission label, file presentation metadata, and share grants (if owner).
 * - NEVER exposes physical file storage keys ({fileStorageKey}.bin), logical storage UUIDs,
 *   filesystem paths, internal SHA-256 checksums, user passwords, or raw binary streams.
 */
public record DocumentDetailViewModel(
        Long id,
        String title,
        String description,
        String category,
        String ownerUsername,
        boolean isOwner,
        String permissionLabel,
        boolean canEdit,
        boolean hasFile,
        String fileOriginalName,
        String fileContentType,
        Long fileSize,
        String formattedFileSize,
        Instant fileUploadedAt,
        Instant createdAt,
        Instant updatedAt,
        List<ShareItemViewModel> shares
) {
    /**
     * Backward-compatible 16-argument constructor for views initialized without category.
     */
    public DocumentDetailViewModel(
            Long id,
            String title,
            String description,
            String ownerUsername,
            boolean isOwner,
            String permissionLabel,
            boolean canEdit,
            boolean hasFile,
            String fileOriginalName,
            String fileContentType,
            Long fileSize,
            String formattedFileSize,
            Instant fileUploadedAt,
            Instant createdAt,
            Instant updatedAt,
            List<ShareItemViewModel> shares
    ) {
        this(id, title, description, null, ownerUsername, isOwner, permissionLabel, canEdit, hasFile, fileOriginalName, fileContentType, fileSize, formattedFileSize, fileUploadedAt, createdAt, updatedAt, shares);
    }

    /**
     * Constructs a safe DocumentDetailViewModel from a Document entity, caller context, and optional shares.
     *
     * @param doc             the Document entity
     * @param currentUsername the authenticated user viewing the page
     * @param permissionLabel the resolved permission level ("OWNER", "EDIT", or "READ")
     * @param shares          active shares on this document (only passed if caller is owner)
     * @return populated DocumentDetailViewModel
     */
    public static DocumentDetailViewModel from(
            Document doc,
            String currentUsername,
            String permissionLabel,
            List<DocumentShare> shares) {
        if (doc == null) {
            return null;
        }

        String ownerName = doc.getOwner() != null ? doc.getOwner().getUsername() : null;
        boolean isOwner = ownerName != null && ownerName.equalsIgnoreCase(currentUsername);
        String resolvedPermission = isOwner ? "OWNER" : (permissionLabel != null ? permissionLabel : "READ");
        boolean canEdit = isOwner || "EDIT".equalsIgnoreCase(resolvedPermission);

        boolean hasFile = doc.hasFile();
        Long size = hasFile ? doc.getFileSize() : null;

        List<ShareItemViewModel> shareViewModels = (isOwner && shares != null)
                ? shares.stream().map(ShareItemViewModel::from).toList()
                : Collections.emptyList();

        return new DocumentDetailViewModel(
                doc.getId(),
                doc.getTitle(),
                doc.getDescription(),
                doc.getCategory(),
                ownerName,
                isOwner,
                resolvedPermission,
                canEdit,
                hasFile,
                hasFile ? doc.getFileOriginalName() : null,
                hasFile ? doc.getFileContentType() : null,
                size,
                DocumentItemViewModel.formatFileSize(size),
                hasFile ? doc.getFileUploadedAt() : null,
                doc.getCreatedAt(),
                doc.getUpdatedAt(),
                shareViewModels
        );
    }
}
