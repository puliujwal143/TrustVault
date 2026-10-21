package com.trustvault.service;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
import com.trustvault.repository.AuditEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Service engine for recording and querying immutable security audit events.
 *
 * <p>Transaction Consistency & Connection Pool Architecture:
 * <ul>
 *   <li><b>Same-Transaction Success Events ({@code Propagation.REQUIRED}):</b> Successful business
 *       operations participate in the caller's active database transaction. If the business mutation
 *       rolls back for any reason, the {@code SUCCESS} audit event rolls back atomically with it.
 *       This guarantees that no phantom {@code SUCCESS} audit record can ever exist in the database.</li>
 *   <li><b>Isolated Denial Events ({@code Propagation.REQUIRES_NEW}):</b> Security violations,
 *       access denials, and unauthorized probes are recorded in a dedicated autonomous transaction.
 *       This ensures that the {@code ACCESS_DENIED} audit record commits and survives even when the
 *       caller's transaction is subsequently rolled back by an authorization exception.</li>
 *   <li><b>Connection-Pool Exhaustion Guardrails:</b>
 *       Because {@code Propagation.REQUIRES_NEW} suspends the outer transaction while retaining its
 *       physical database connection, the thread temporarily holds two connections simultaneously.
 *       To eliminate pool starvation and deadlock risks:
 *       <ol>
 *         <li>The denial transaction is kept strictly minimal: a single indexed {@code save()} that
 *             commits immediately and releases the second connection within milliseconds.</li>
 *         <li>Denial recording is wrapped in a fail-safe try-catch: if database connectivity or connection
 *             acquisition fails, an error is logged to SLF4J without suppressing or bypassing the security
 *             denial decision.</li>
 *         <li>Production pool sizing formula: {@code maximum-pool-size} must be configured to at least
 *             {@code 2 * maxConcurrentWorkerThreads}.</li>
 *       </ol>
 *   </li>
 * </ul>
 *
 * <p>Privacy & Data Hygiene Guardrails:
 * <ul>
 *   <li>Never accepts or logs passwords, session identifiers, CSRF tokens, document titles,
 *       descriptions, or file contents.</li>
 *   <li>Sanitizes, strips control characters, and length-bounds all string metadata before persistence.</li>
 * </ul>
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private static final int MAX_USERNAME_LENGTH = 50;
    private static final int MAX_IP_LENGTH = 45;
    private static final int MAX_DETAILS_LENGTH = 500;

    private final AuditEventRepository auditEventRepository;

    public AuditService(AuditEventRepository auditEventRepository) {
        this.auditEventRepository = auditEventRepository;
    }

    /**
     * Records an audit event participating in the current business transaction.
     *
     * <p>If an active transaction exists, this method joins it ({@code Propagation.REQUIRED}).
     * If the business transaction rolls back, this audit record rolls back with it, preventing
     * phantom success records.
     *
     * @param action             the discrete action verb (required)
     * @param outcome            the outcome of the operation (required)
     * @param actorUsername      the acting user's username (required)
     * @param documentId         the affected document database ID (optional)
     * @param documentStorageKey the affected document immutable storage UUID (optional)
     * @param targetUsername     the target or recipient username (optional)
     * @param clientIp           the client IP address (optional)
     * @param details            sanitized, safe metadata or status descriptors (optional)
     * @return the persisted AuditEvent entity
     * @throws IllegalArgumentException if action, outcome, or actorUsername is null/blank
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AuditEvent recordEvent(
            AuditAction action,
            AuditOutcome outcome,
            String actorUsername,
            Long documentId,
            UUID documentStorageKey,
            String targetUsername,
            String clientIp,
            String details) {

        Objects.requireNonNull(action, "AuditAction must not be null");
        Objects.requireNonNull(outcome, "AuditOutcome must not be null");

        String sanitizedActor = sanitize(actorUsername, MAX_USERNAME_LENGTH);
        if (sanitizedActor == null) {
            throw new IllegalArgumentException("Actor username must not be null or blank");
        }

        String sanitizedTarget = sanitize(targetUsername, MAX_USERNAME_LENGTH);
        String sanitizedIp = sanitize(clientIp, MAX_IP_LENGTH);
        String sanitizedDetails = sanitize(details, MAX_DETAILS_LENGTH);

        AuditEvent event = new AuditEvent(
                sanitizedActor,
                action,
                documentId,
                documentStorageKey,
                sanitizedTarget,
                outcome,
                sanitizedIp,
                sanitizedDetails
        );

        AuditEvent saved = auditEventRepository.save(event);
        log.debug("Recorded audit event: action={}, outcome={}, actor={}, docId={}",
                saved.getAction(), saved.getOutcome(), saved.getActorUsername(), saved.getDocumentId());
        return saved;
    }

    /**
     * Convenience method for recording a successful business mutation in the current transaction.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public AuditEvent recordSuccess(
            AuditAction action,
            String actorUsername,
            Long documentId,
            UUID documentStorageKey,
            String targetUsername,
            String clientIp,
            String details) {
        return recordEvent(action, AuditOutcome.SUCCESS, actorUsername, documentId, documentStorageKey, targetUsername, clientIp, details);
    }

    /**
     * Records an authorization rejection or security denial in an autonomous transaction
     * ({@code Propagation.REQUIRES_NEW}).
     *
     * <p>This transaction commits independently and survives even when the calling transaction
     * is rolled back due to an authorization exception (403 or 404).
     *
     * <p>Fail-safe behavior: If connection acquisition or database insert fails during denial
     * logging, a warning is logged via SLF4J and the method returns {@code Optional.empty()}
     * rather than throwing an exception that could mask or alter the security denial.
     *
     * @param actorUsername      the username attempting the unauthorized action (required)
     * @param documentId         the requested document ID (optional)
     * @param documentStorageKey the requested document storage UUID (optional)
     * @param targetUsername     the target username if applicable (optional)
     * @param clientIp           the client IP address (optional)
     * @param denialReason       standardized denial reason descriptor (optional)
     * @return an Optional containing the saved AuditEvent, or empty if fail-safe logging activated
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Optional<AuditEvent> recordSecurityDenial(
            String actorUsername,
            Long documentId,
            UUID documentStorageKey,
            String targetUsername,
            String clientIp,
            String denialReason) {

        try {
            String sanitizedActor = sanitize(actorUsername, MAX_USERNAME_LENGTH);
            if (sanitizedActor == null) {
                sanitizedActor = "ANONYMOUS";
            }

            String sanitizedTarget = sanitize(targetUsername, MAX_USERNAME_LENGTH);
            String sanitizedIp = sanitize(clientIp, MAX_IP_LENGTH);
            String sanitizedReason = sanitize(denialReason, MAX_DETAILS_LENGTH);

            AuditEvent event = new AuditEvent(
                    sanitizedActor,
                    AuditAction.ACCESS_DENIED,
                    documentId,
                    documentStorageKey,
                    sanitizedTarget,
                    AuditOutcome.DENIED,
                    sanitizedIp,
                    sanitizedReason
            );

            AuditEvent saved = auditEventRepository.save(event);
            log.warn("Security denial audited: actor='{}', docId={}, target='{}', reason='{}'",
                    sanitizedActor, documentId, sanitizedTarget, sanitizedReason);
            return Optional.of(saved);

        } catch (Exception ex) {
            // Fail-safe: database failure or pool timeout during denial auditing must not swallow authorization rejection
            log.error("Failed to persist security denial audit event for actor '{}': {}", actorUsername, ex.getMessage(), ex);
            return Optional.empty();
        }
    }

    // =========================================================================
    // Read-only query methods (for security auditing & administrative review)
    // =========================================================================

    @Transactional(readOnly = true)
    public Optional<AuditEvent> getEventById(Long id) {
        return auditEventRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<AuditEvent> getEventByEventId(UUID eventId) {
        return auditEventRepository.findByEventId(eventId);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getEventsForDocument(Long documentId) {
        if (documentId == null) {
            return List.of();
        }
        return auditEventRepository.findByDocumentIdOrderByTimestampDesc(documentId);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getEventsForDocumentStorageKey(UUID documentStorageKey) {
        if (documentStorageKey == null) {
            return List.of();
        }
        return auditEventRepository.findByDocumentStorageKeyOrderByTimestampDesc(documentStorageKey);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getEventsForActor(String actorUsername) {
        if (actorUsername == null || actorUsername.isBlank()) {
            return List.of();
        }
        return auditEventRepository.findByActorUsernameOrderByTimestampDesc(actorUsername.trim());
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getEventsByAction(AuditAction action) {
        if (action == null) {
            return List.of();
        }
        return auditEventRepository.findByActionOrderByTimestampDesc(action);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> getEventsByOutcome(AuditOutcome outcome) {
        if (outcome == null) {
            return List.of();
        }
        return auditEventRepository.findByOutcomeOrderByTimestampDesc(outcome);
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> getAllEvents(Pageable pageable) {
        return auditEventRepository.findAll(pageable != null ? pageable : Pageable.unpaged());
    }

    @Transactional(readOnly = true)
    public long getEventCount() {
        return auditEventRepository.count();
    }

    // =========================================================================
    // Sanitization Helpers
    // =========================================================================

    private String sanitize(String input, int maxLength) {
        if (input == null) {
            return null;
        }
        String trimmed = input.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        // Normalize newlines, carriage returns, and tabs to prevent log forging
        String normalized = trimmed.replaceAll("[\\r\\n\\t]", " ");
        if (normalized.length() > maxLength) {
            return normalized.substring(0, maxLength);
        }
        return normalized;
    }
}
