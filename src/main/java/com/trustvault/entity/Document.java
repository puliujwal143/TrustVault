package com.trustvault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/**
 * Persistent document entity representing document metadata and ownership.
 *
 * Security & Data Model Requirements:
 * - Each document has exactly ONE owner, linked to a persistent User.
 * - Identified externally by an immutable, non-predictable UUID storageKey to prepare for
 *   private disk storage in subsequent phases.
 * - Title is required, non-blank, and bounded to 255 characters.
 * - Description is optional and bounded to 1000 characters.
 * - Creation and update timestamps are tracked automatically.
 * - JPA equals() and hashCode() are based on the immutable UUID storageKey, guaranteeing
 *   stable identity across all JPA lifecycle states (Transient -> Persistent -> Detached).
 */
@Entity
@Table(name = "documents")
public class Document {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Non-predictable UUID identifier. Serves as internal reference for private disk
     * storage in later phases, preventing IDOR predictability and filename collisions.
     * Initialized upon construction and immutable thereafter.
     */
    @NotNull
    @Column(name = "storage_key", nullable = false, unique = true, updatable = false)
    private UUID storageKey;

    @NotBlank
    @Size(min = 1, max = 255)
    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Size(max = 1000)
    @Column(name = "description", length = 1000)
    private String description;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Original client-supplied filename (e.g., "report.pdf").
     * Decoupled from private disk storage where files are stored using immutable UUID keys ({storageKey}.bin).
     * Null for metadata-only documents.
     */
    @Size(max = 255, message = "Original filename must not exceed 255 characters")
    @Column(name = "file_original_name", length = 255)
    private String fileOriginalName;

    /**
     * Validated MIME content type of the uploaded file payload (e.g., "application/pdf").
     * Null for metadata-only documents.
     */
    @Size(max = 100, message = "Content type must not exceed 100 characters")
    @Column(name = "file_content_type", length = 100)
    private String fileContentType;

    /**
     * Size of the stored file payload in bytes.
     * Null for metadata-only documents. Must be non-negative when present (0 or greater).
     */
    @PositiveOrZero(message = "File size must be greater than or equal to 0")
    @Column(name = "file_size")
    private Long fileSize;

    /**
     * SHA-256 hexadecimal checksum (exactly 64 lowercase or uppercase hex characters).
     * Used for integrity verification and deduplication detection.
     * Null for metadata-only documents.
     */
    @Pattern(regexp = "^[0-9a-fA-F]{64}$", message = "File checksum must be a 64-character hexadecimal SHA-256 hash")
    @Size(max = 64)
    @Column(name = "file_checksum", length = 64)
    private String fileChecksum;

    /**
     * Timestamp when the file was uploaded or replaced in storage.
     * Null for metadata-only documents.
     */
    @Column(name = "file_uploaded_at")
    private Instant fileUploadedAt;

    public Document() {
        // Assign UUID eagerly so entity has stable identity even in transient state
        this.storageKey = UUID.randomUUID();
    }

    public Document(String title, String description, User owner) {
        this();
        this.title = title != null ? title.trim() : null;
        this.description = description != null ? description.trim() : null;
        this.owner = owner;
    }

    public Document(UUID storageKey, String title, String description, User owner) {
        this.storageKey = storageKey != null ? storageKey : UUID.randomUUID();
        this.title = title != null ? title.trim() : null;
        this.description = description != null ? description.trim() : null;
        this.owner = owner;
    }

    @PrePersist
    protected void onCreate() {
        Instant now = Instant.now();
        if (this.createdAt == null) {
            this.createdAt = now;
        }
        if (this.updatedAt == null) {
            this.updatedAt = now;
        }
        if (this.storageKey == null) {
            this.storageKey = UUID.randomUUID();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UUID getStorageKey() {
        return storageKey;
    }

    public void setStorageKey(UUID storageKey) {
        this.storageKey = storageKey;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title != null ? title.trim() : null;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description != null ? description.trim() : null;
    }

    public User getOwner() {
        return owner;
    }

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    // File Metadata Accessors & Helpers

    public String getFileOriginalName() {
        return fileOriginalName;
    }

    public void setFileOriginalName(String fileOriginalName) {
        this.fileOriginalName = fileOriginalName != null ? fileOriginalName.trim() : null;
    }

    public String getFileContentType() {
        return fileContentType;
    }

    public void setFileContentType(String fileContentType) {
        this.fileContentType = fileContentType != null ? fileContentType.trim() : null;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }

    public String getFileChecksum() {
        return fileChecksum;
    }

    public void setFileChecksum(String fileChecksum) {
        this.fileChecksum = fileChecksum != null ? fileChecksum.trim().toLowerCase(java.util.Locale.ROOT) : null;
    }

    public Instant getFileUploadedAt() {
        return fileUploadedAt;
    }

    public void setFileUploadedAt(Instant fileUploadedAt) {
        this.fileUploadedAt = fileUploadedAt;
    }

    private static final java.util.regex.Pattern SHA256_PATTERN = java.util.regex.Pattern.compile("^[0-9a-fA-F]{64}$");

    /**
     * Checks whether this document has an associated binary file payload in storage.
     *
     * <p>Semantics:
     * <ul>
     *   <li>Returns {@code true} only when all five file metadata fields are present:
     *       {@code fileOriginalName != null}, {@code fileContentType != null}, {@code fileSize != null},
     *       {@code fileChecksum != null}, and {@code fileUploadedAt != null}.</li>
     *   <li>A zero-byte file ({@code fileSize == 0}) is valid and treated as present if all fields are populated.</li>
     *   <li>Returns {@code false} if any file metadata field is null (including metadata-only documents).</li>
     * </ul>
     *
     * @return true if an associated file payload is fully recorded; false otherwise
     */
    public boolean hasFile() {
        return this.fileOriginalName != null
                && this.fileContentType != null
                && this.fileSize != null
                && this.fileChecksum != null
                && this.fileUploadedAt != null;
    }

    /**
     * Verifies that the file metadata attributes are in a consistent state:
     * either completely populated (all 5 file metadata fields non-null)
     * or completely absent (all 5 file metadata fields null).
     *
     * @return true if metadata is fully populated or fully absent; false if partially populated
     */
    public boolean isFileMetadataConsistent() {
        boolean allNull = fileOriginalName == null
                && fileContentType == null
                && fileSize == null
                && fileChecksum == null
                && fileUploadedAt == null;
        return allNull || hasFile();
    }

    /**
     * Associates or replaces binary file metadata for this document atomically after strict validation.
     *
     * <p>Validation rules:
     * <ul>
     *   <li>Original filename must not be null or blank, and must not exceed 255 characters.</li>
     *   <li>Content type must not be null or blank, and must not exceed 100 characters.</li>
     *   <li>File size must not be null and must be non-negative (>= 0).</li>
     *   <li>File checksum must not be null and must be exactly 64 hexadecimal characters.</li>
     *   <li>Upload timestamp defaults to {@link Instant#now()} if null.</li>
     * </ul>
     *
     * <p>Entity fields are not mutated until all arguments pass validation.
     *
     * @param originalName client-supplied filename (max 255 chars)
     * @param contentType  validated MIME content type (max 100 chars)
     * @param size         byte length of the file (non-negative)
     * @param checksum     SHA-256 hexadecimal checksum (64 chars)
     * @param uploadedAt   timestamp of upload completion (defaults to Instant.now() if null)
     * @throws IllegalArgumentException if any argument violates validation rules
     */
    public void setFileMetadata(String originalName, String contentType, Long size, String checksum, Instant uploadedAt) {
        if (originalName == null || originalName.isBlank()) {
            throw new IllegalArgumentException("Original filename must not be null or blank");
        }
        String trimmedName = originalName.trim();
        if (trimmedName.length() > 255) {
            throw new IllegalArgumentException("Original filename must not exceed 255 characters");
        }

        if (contentType == null || contentType.isBlank()) {
            throw new IllegalArgumentException("Content type must not be null or blank");
        }
        String trimmedContentType = contentType.trim();
        if (trimmedContentType.length() > 100) {
            throw new IllegalArgumentException("Content type must not exceed 100 characters");
        }

        if (size == null || size < 0) {
            throw new IllegalArgumentException("File size must not be null and must be non-negative");
        }

        if (checksum == null) {
            throw new IllegalArgumentException("File checksum must not be null");
        }
        String normalizedChecksum = checksum.trim().toLowerCase(Locale.ROOT);
        if (!SHA256_PATTERN.matcher(normalizedChecksum).matches()) {
            throw new IllegalArgumentException("File checksum must be a 64-character hexadecimal SHA-256 hash");
        }

        Instant uploadTimestamp = uploadedAt != null ? uploadedAt : Instant.now();

        // Atomically mutate entity fields only after all arguments are validated
        this.fileOriginalName = trimmedName;
        this.fileContentType = trimmedContentType;
        this.fileSize = size;
        this.fileChecksum = normalizedChecksum;
        this.fileUploadedAt = uploadTimestamp;
    }

    /**
     * Clears all file metadata attributes, reverting the document to a metadata-only state.
     */
    public void clearFileMetadata() {
        this.fileOriginalName = null;
        this.fileContentType = null;
        this.fileSize = null;
        this.fileChecksum = null;
        this.fileUploadedAt = null;
    }

    /**
     * JPA-safe equality based on immutable UUID storageKey.
     * Uses other.getStorageKey() to support Hibernate lazy proxies.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Document other)) return false;
        return storageKey != null && storageKey.equals(other.getStorageKey());
    }

    /**
     * Invariant hash code based on immutable UUID storageKey.
     * Guarantees the hash code remains unchanged across all JPA persistence states.
     */
    @Override
    public int hashCode() {
        return storageKey != null ? Objects.hash(storageKey) : getClass().hashCode();
    }

    @Override
    public String toString() {
        return "Document{" +
                "id=" + id +
                ", storageKey=" + storageKey +
                ", title='" + title + '\'' +
                ", hasFile=" + hasFile() +
                ", fileSize=" + fileSize +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}
