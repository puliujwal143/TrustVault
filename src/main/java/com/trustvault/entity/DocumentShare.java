package com.trustvault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.Objects;

/**
 * Persistent entity representing access permission granted on a Document to a specific User.
 *
 * Security & Data Model Requirements:
 * - Links a document to a named grantee user with an explicit SharePermission (READ or EDIT).
 * - Enforces a database-level unique constraint on (document_id, grantee_id) to prevent duplicate grants.
 * - Changing permission between READ and EDIT modifies the existing record rather than creating duplicates.
 * - Tracks the timestamp when access was granted.
 * - JPA equals() and hashCode() are based on the natural composite identity (document, grantee),
 *   guaranteeing lifecycle stability across Transient -> Persistent states.
 */
@Entity
@Table(
        name = "document_shares",
        uniqueConstraints = @UniqueConstraint(name = "uq_document_grantee", columnNames = {"document_id", "grantee_id"})
)
public class DocumentShare {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "document_id", nullable = false)
    @org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
    private Document document;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "grantee_id", nullable = false)
    @org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
    private User grantee;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "permission", nullable = false, length = 20)
    private SharePermission permission;

    @Column(name = "granted_at", nullable = false, updatable = false)
    private Instant grantedAt;

    public DocumentShare() {
        // Default constructor required by JPA
    }

    public DocumentShare(Document document, User grantee, SharePermission permission) {
        this.document = Objects.requireNonNull(document, "Document must not be null");
        this.grantee = Objects.requireNonNull(grantee, "Grantee must not be null");
        this.permission = Objects.requireNonNull(permission, "Permission must not be null");
    }

    @PrePersist
    protected void onCreate() {
        if (this.grantedAt == null) {
            this.grantedAt = Instant.now();
        }
    }

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Document getDocument() {
        return document;
    }

    public void setDocument(Document document) {
        this.document = Objects.requireNonNull(document, "Document must not be null");
    }

    public User getGrantee() {
        return grantee;
    }

    public void setGrantee(User grantee) {
        this.grantee = Objects.requireNonNull(grantee, "Grantee must not be null");
    }

    public SharePermission getPermission() {
        return permission;
    }

    public void setPermission(SharePermission permission) {
        this.permission = Objects.requireNonNull(permission, "Permission must not be null");
    }

    public Instant getGrantedAt() {
        return grantedAt;
    }

    public void setGrantedAt(Instant grantedAt) {
        this.grantedAt = grantedAt;
    }

    /**
     * JPA-safe equality based on natural composite key (document, grantee).
     * Uses getters other.getDocument() and other.getGrantee() to support Hibernate lazy proxies.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DocumentShare other)) return false;
        return document != null && grantee != null
                && document.equals(other.getDocument())
                && grantee.equals(other.getGrantee());
    }

    /**
     * Invariant hash code based on immutable natural keys of document (storageKey) and grantee (username).
     * Guarantees the hash code remains unchanged when the entity transitions from
     * transient to persistent state upon database insertion.
     */
    @Override
    public int hashCode() {
        return Objects.hash(
                document != null ? document.getStorageKey() : null,
                grantee != null ? grantee.getUsername() : null
        );
    }

    @Override
    public String toString() {
        return "DocumentShare{" +
                "id=" + id +
                ", permission=" + permission +
                ", grantedAt=" + grantedAt +
                '}';
    }
}
