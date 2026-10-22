package com.trustvault.repository;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Append-only Spring Data repository for AuditEvent entities.
 *
 * <p>Security & Immutability Design:
 * <ul>
 *   <li>Extends Spring Data's root {@link Repository} marker interface instead of
 *       {@code CrudRepository} or {@code JpaRepository}.</li>
 *   <li>Exposes ONLY {@code save()} and necessary read query methods.</li>
 *   <li>Explicitly omits all delete, remove, and update methods, ensuring application
 *       services cannot delete or mutate historical audit records through repository operations.</li>
 * </ul>
 */
@org.springframework.stereotype.Repository
public interface AuditEventRepository extends Repository<AuditEvent, Long> {

    /**
     * Persists an audit event to the append-only audit trail.
     *
     * @param event the audit event to persist
     * @return the persisted AuditEvent entity
     */
    AuditEvent save(AuditEvent event);

    /**
     * Finds an audit event by its database primary key.
     *
     * @param id the primary key
     * @return an Optional containing the AuditEvent if found
     */
    Optional<AuditEvent> findById(Long id);

    /**
     * Finds an audit event by its immutable public UUID event identifier.
     *
     * @param eventId the public event UUID
     * @return an Optional containing the AuditEvent if found
     */
    Optional<AuditEvent> findByEventId(UUID eventId);

    /**
     * Retrieves all audit events associated with a specific document ID,
     * ordered chronologically descending (newest first).
     *
     * @param documentId the document ID
     * @return list of audit events
     */
    List<AuditEvent> findByDocumentIdOrderByTimestampDesc(Long documentId);

    /**
     * Retrieves all audit events associated with a specific document storage key,
     * ordered chronologically descending (newest first).
     * Preserved even if the underlying document row is deleted.
     *
     * @param documentStorageKey the immutable storage UUID
     * @return list of audit events
     */
    List<AuditEvent> findByDocumentStorageKeyOrderByTimestampDesc(UUID documentStorageKey);

    /**
     * Retrieves all audit events executed by a specific actor username,
     * ordered chronologically descending.
     *
     * @param actorUsername the username of the actor
     * @return list of audit events
     */
    List<AuditEvent> findByActorUsernameOrderByTimestampDesc(String actorUsername);

    /**
     * Retrieves all audit events for a specific action type,
     * ordered chronologically descending.
     *
     * @param action the action type
     * @return list of audit events
     */
    List<AuditEvent> findByActionOrderByTimestampDesc(AuditAction action);

    /**
     * Retrieves all audit events with a specific outcome,
     * ordered chronologically descending.
     *
     * @param outcome the outcome status
     * @return list of audit events
     */
    List<AuditEvent> findByOutcomeOrderByTimestampDesc(AuditOutcome outcome);

    /**
     * Retrieves a paginated slice of audit events for administrative review.
     *
     * @param pageable pagination parameters
     * @return page of audit events
     */
    Page<AuditEvent> findAll(Pageable pageable);

    /**
     * Retrieves a paginated slice of audit events executed by a specific actor username,
     * ordered chronologically descending.
     *
     * @param actorUsername the username of the actor
     * @param pageable      pagination parameters
     * @return page of audit events
     */
    Page<AuditEvent> findByActorUsernameOrderByTimestampDesc(String actorUsername, Pageable pageable);

    /**
     * Returns the total count of recorded audit events.
     *
     * @return total event count
     */
    long count();

    /**
     * Returns the total count of recorded audit events for a specific actor username.
     *
     * @param actorUsername the username of the actor
     * @return total event count for the actor
     */
    long countByActorUsername(String actorUsername);

    /**
     * Returns the total count of recorded audit events for a specific outcome.
     *
     * @param outcome the outcome status
     * @return total event count for the outcome
     */
    long countByOutcome(AuditOutcome outcome);

    /**
     * Returns the total count of recorded audit events for a specific actor and outcome.
     *
     * @param actorUsername the username of the actor
     * @param outcome       the outcome status
     * @return total event count for the actor and outcome
     */
    long countByActorUsernameAndOutcome(String actorUsername, AuditOutcome outcome);
}
