package com.trustvault.dto;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;

import java.time.Instant;
import java.util.UUID;

/**
 * Safe view model representing an audit event row on the audit history view.
 *
 * Security Requirements:
 * - Decouples view rendering from JPA entities, adhering to spring.jpa.open-in-view=false.
 * - Exposes only client-safe audit fields: id, eventId, timestamp, actorUsername,
 *   action (and human-readable label), documentId reference, targetUsername, outcome, clientIp, details.
 * - NEVER exposes physical filesystem paths, blob storage keys, passwords, session identifiers, or raw secrets.
 */
public record AuditItemViewModel(
        Long id,
        UUID eventId,
        Instant timestamp,
        String actorUsername,
        AuditAction action,
        String actionLabel,
        Long documentId,
        String targetUsername,
        AuditOutcome outcome,
        String clientIp,
        String details
) {
    public static AuditItemViewModel from(AuditEvent event) {
        if (event == null) {
            return null;
        }

        return new AuditItemViewModel(
                event.getId(),
                event.getEventId(),
                event.getTimestamp(),
                event.getActorUsername(),
                event.getAction(),
                formatAction(event.getAction()),
                event.getDocumentId(),
                event.getTargetUsername(),
                event.getOutcome(),
                event.getClientIp(),
                event.getDetails()
        );
    }

    public static String formatAction(AuditAction action) {
        if (action == null) return "Unknown";
        return switch (action) {
            case DOCUMENT_CREATE -> "Document Created";
            case DOCUMENT_READ -> "Document Viewed";
            case DOCUMENT_UPDATE -> "Document Updated";
            case DOCUMENT_DELETE -> "Document Deleted";
            case SHARE_GRANT -> "Access Granted";
            case SHARE_UPDATE -> "Access Updated";
            case SHARE_REVOKE -> "Access Revoked";
            case USER_DEACTIVATE -> "User Deactivated";
            case USER_REACTIVATE -> "User Reactivated";
            case PASSWORD_CHANGE -> "Password Changed";
            case ACCESS_DENIED -> "Access Denied";
            case FILE_UPLOAD -> "File Uploaded";
            case FILE_DOWNLOAD -> "File Downloaded";
        };
    }
}
