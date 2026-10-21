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
import jakarta.validation.constraints.Size;

import java.time.Instant;
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
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}
