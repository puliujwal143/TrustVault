package com.trustvault.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.hibernate.annotations.Immutable;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable audit event entity representing a security-relevant action in TrustVault.
 *
 * <p>Security & Immutability Design:
 * <ul>
 *   <li>Annotated with Hibernate {@link Immutable} to instruct the persistence context
 *       that instances are read-only and dirty checking should never issue SQL UPDATEs.</li>
 *   <li>All column mappings specify {@code updatable = false}.</li>
 *   <li>Exposes only getter methods; no public setters are provided.</li>
 *   <li>{@code document_id} and {@code document_storage_key} are recorded as independent
 *       audit snapshots with no foreign key cascade constraint, ensuring that document
 *       deletion never mutates or cascades deletions to historical audit rows.</li>
 *   <li>JPA {@code equals()} and {@code hashCode()} are based on the immutable UUID {@code eventId},
 *       guaranteeing stable identity across all persistence lifecycle states.</li>
 * </ul>
 */
@Entity
@Table(name = "audit_events")
@Immutable
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Column(name = "event_id", nullable = false, unique = true, updatable = false)
    private UUID eventId;

    @NotNull
    @Column(name = "timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    @NotBlank
    @Size(max = 50)
    @Column(name = "actor_username", nullable = false, updatable = false, length = 50)
    private String actorUsername;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, updatable = false, length = 50)
    private AuditAction action;

    @Column(name = "document_id", updatable = false)
    private Long documentId;

    @Column(name = "document_storage_key", updatable = false)
    private UUID documentStorageKey;

    @Size(max = 50)
    @Column(name = "target_username", updatable = false, length = 50)
    private String targetUsername;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, updatable = false, length = 20)
    private AuditOutcome outcome;

    @Size(max = 45)
    @Column(name = "client_ip", updatable = false, length = 45)
    private String clientIp;

    @Size(max = 500)
    @Column(name = "details", updatable = false, length = 500)
    private String details;

    /**
     * Default constructor required by JPA.
     * Initializes default UUID and timestamp for transient instances.
     */
    protected AuditEvent() {
        this.eventId = UUID.randomUUID();
        this.timestamp = Instant.now();
    }

    /**
     * Creates a new immutable AuditEvent with a generated eventId and current timestamp.
     *
     * @param actorUsername      the username of the acting principal (required, max 50 chars)
     * @param action             the discrete audit action verb (required)
     * @param documentId         the optional database ID of the affected document
     * @param documentStorageKey the optional immutable storage UUID of the affected document
     * @param targetUsername     the optional target username (grantee, affected user)
     * @param outcome            the outcome of the operation (required: SUCCESS, DENIED, FAILURE)
     * @param clientIp           the optional client IPv4 or IPv6 address (max 45 chars)
     * @param details            the optional safe metadata or denial reason (max 500 chars)
     */
    public AuditEvent(
            String actorUsername,
            AuditAction action,
            Long documentId,
            UUID documentStorageKey,
            String targetUsername,
            AuditOutcome outcome,
            String clientIp,
            String details) {
        this();
        this.actorUsername = actorUsername != null ? actorUsername.trim() : null;
        this.action = action;
        this.documentId = documentId;
        this.documentStorageKey = documentStorageKey;
        this.targetUsername = targetUsername != null ? targetUsername.trim() : null;
        this.outcome = outcome;
        this.clientIp = clientIp != null ? clientIp.trim() : null;
        this.details = details != null ? details.trim() : null;
    }

    /**
     * Full constructor for testing or specific event creation with explicit eventId and timestamp.
     */
    public AuditEvent(
            UUID eventId,
            Instant timestamp,
            String actorUsername,
            AuditAction action,
            Long documentId,
            UUID documentStorageKey,
            String targetUsername,
            AuditOutcome outcome,
            String clientIp,
            String details) {
        this.eventId = eventId != null ? eventId : UUID.randomUUID();
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.actorUsername = actorUsername != null ? actorUsername.trim() : null;
        this.action = action;
        this.documentId = documentId;
        this.documentStorageKey = documentStorageKey;
        this.targetUsername = targetUsername != null ? targetUsername.trim() : null;
        this.outcome = outcome;
        this.clientIp = clientIp != null ? clientIp.trim() : null;
        this.details = details != null ? details.trim() : null;
    }

    @PrePersist
    protected void onCreate() {
        if (this.eventId == null) {
            this.eventId = UUID.randomUUID();
        }
        if (this.timestamp == null) {
            this.timestamp = Instant.now();
        }
    }

    // Getters only (no setters to enforce entity-level immutability)

    public Long getId() {
        return id;
    }

    public UUID getEventId() {
        return eventId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getActorUsername() {
        return actorUsername;
    }

    public AuditAction getAction() {
        return action;
    }

    public Long getDocumentId() {
        return documentId;
    }

    public UUID getDocumentStorageKey() {
        return documentStorageKey;
    }

    public String getTargetUsername() {
        return targetUsername;
    }

    public AuditOutcome getOutcome() {
        return outcome;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getDetails() {
        return details;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuditEvent other)) return false;
        return eventId != null && eventId.equals(other.getEventId());
    }

    @Override
    public int hashCode() {
        return eventId != null ? Objects.hash(eventId) : getClass().hashCode();
    }

    @Override
    public String toString() {
        return "AuditEvent{" +
                "id=" + id +
                ", eventId=" + eventId +
                ", timestamp=" + timestamp +
                ", actorUsername='" + actorUsername + '\'' +
                ", action=" + action +
                ", documentId=" + documentId +
                ", documentStorageKey=" + documentStorageKey +
                ", targetUsername='" + targetUsername + '\'' +
                ", outcome=" + outcome +
                ", clientIp='" + clientIp + '\'' +
                ", details='" + details + '\'' +
                '}';
    }
}
