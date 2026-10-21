package com.trustvault.service;

import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.exception.ResourceNotFoundException;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Central authorization service for document ownership and share permissions.
 *
 * Security Requirements Enforced:
 * 1. Each document has exactly ONE owner who holds full authority (read, edit, delete, share).
 * 2. Grantees with READ can view document metadata/content but cannot modify or share.
 * 3. Grantees with EDIT can view and modify document metadata/content but cannot delete or share.
 * 4. ROLE_ADMIN does NOT bypass document authorization; private documents remain private.
 * 5. BOLA / IDOR Defense: Requests for documents by users with no grant return ResourceNotFoundException (404),
 *    making unshared documents indistinguishable from non-existent documents to stop ID enumeration.
 * 6. Authorized grantees attempting operations beyond their permission level receive AccessDeniedException (403).
 * 7. Disabled accounts (enabled = false) are denied access immediately on all operations.
 * 8. Permissions are always re-evaluated against the database and never cached in the HTTP session.
 */
@Service
@Transactional(readOnly = true)
public class DocumentAuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(DocumentAuthorizationService.class);

    private final DocumentRepository documentRepository;
    private final DocumentShareRepository documentShareRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    public DocumentAuthorizationService(
            DocumentRepository documentRepository,
            DocumentShareRepository documentShareRepository,
            UserRepository userRepository) {
        this(documentRepository, documentShareRepository, userRepository, null);
    }

    @Autowired
    public DocumentAuthorizationService(
            DocumentRepository documentRepository,
            DocumentShareRepository documentShareRepository,
            UserRepository userRepository,
            AuditService auditService) {
        this.documentRepository = documentRepository;
        this.documentShareRepository = documentShareRepository;
        this.userRepository = userRepository;
        this.auditService = auditService;
    }

    /**
     * Checks whether the user is the owner of the document and has an active, enabled account.
     *
     * @param documentId the document ID
     * @param username   the username to verify
     * @return true if the user is the owner and enabled; false otherwise
     */
    public boolean isOwner(Long documentId, String username) {
        if (documentId == null || username == null || username.isBlank()) {
            return false;
        }

        String normalizedUsername = username.trim();
        Optional<User> userOpt = userRepository.findByUsername(normalizedUsername);
        if (userOpt.isEmpty() || !userOpt.get().isEnabled()) {
            return false;
        }

        return documentRepository.existsByIdAndOwnerUsername(documentId, normalizedUsername);
    }

    /**
     * Checks whether the user has permission to read the document (as owner or via READ/EDIT share).
     *
     * @param documentId the document ID
     * @param username   the username to verify
     * @return true if the user can read the document; false otherwise
     */
    public boolean canRead(Long documentId, String username) {
        if (documentId == null || username == null || username.isBlank()) {
            return false;
        }

        String normalizedUsername = username.trim();
        Optional<User> userOpt = userRepository.findByUsername(normalizedUsername);
        if (userOpt.isEmpty() || !userOpt.get().isEnabled()) {
            return false;
        }

        Optional<Document> docOpt = documentRepository.findById(documentId);
        if (docOpt.isEmpty()) {
            return false;
        }
        Document document = docOpt.get();

        // Policy: when a document owner is disabled, their documents are unavailable to anyone
        if (!document.getOwner().isEnabled()) {
            return false;
        }

        // Owner can always read
        if (document.getOwner().getUsername().equalsIgnoreCase(normalizedUsername)) {
            return true;
        }

        // Check for active share grant (both READ and EDIT permit reading)
        return documentShareRepository.findByDocumentIdAndGranteeUsername(documentId, normalizedUsername)
                .map(share -> share.getPermission().allowsRead())
                .orElse(false);
    }

    /**
     * Checks whether the user has permission to edit the document (as owner or via EDIT share).
     *
     * @param documentId the document ID
     * @param username   the username to verify
     * @return true if the user can edit the document; false otherwise
     */
    public boolean canEdit(Long documentId, String username) {
        if (documentId == null || username == null || username.isBlank()) {
            return false;
        }

        String normalizedUsername = username.trim();
        Optional<User> userOpt = userRepository.findByUsername(normalizedUsername);
        if (userOpt.isEmpty() || !userOpt.get().isEnabled()) {
            return false;
        }

        Optional<Document> docOpt = documentRepository.findById(documentId);
        if (docOpt.isEmpty()) {
            return false;
        }
        Document document = docOpt.get();

        // Policy: when a document owner is disabled, their documents are unavailable to anyone
        if (!document.getOwner().isEnabled()) {
            return false;
        }

        // Owner can always edit
        if (document.getOwner().getUsername().equalsIgnoreCase(normalizedUsername)) {
            return true;
        }

        // Check for active share grant with EDIT permission
        return documentShareRepository.findByDocumentIdAndGranteeUsername(documentId, normalizedUsername)
                .map(share -> share.getPermission().allowsEdit())
                .orElse(false);
    }

    /**
     * Retrieves a document while strictly enforcing the required permission level (read-only lookup).
     *
     * Anti-Enumeration (404 vs 403) Rules:
     * - If document does not exist: throws ResourceNotFoundException (404).
     * - If caller has no grant and is not owner: throws ResourceNotFoundException (404) to prevent IDOR existence leaks.
     * - If caller is a known grantee but lacks required permission: throws AccessDeniedException (403).
     * - If caller is a disabled user: throws ResourceNotFoundException (404).
     * - If document owner is disabled: throws ResourceNotFoundException (404) to make disabled owners' documents unavailable.
     *
     * @param documentId         the document ID to retrieve
     * @param username           the authenticated username requesting access
     * @param requiredPermission the minimum required permission (READ or EDIT)
     * @return the authorized Document entity
     * @throws ResourceNotFoundException if document is not found or caller has no discovery rights (404)
     * @throws AccessDeniedException     if caller is an existing grantee lacking the required permission (403)
     */
    public Document getAuthorizedDocument(Long documentId, String username, SharePermission requiredPermission) {
        Objects.requireNonNull(documentId, "Document ID must not be null");
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> {
                    auditSecurityDenial(username, documentId, null, null, null, "reason=NOT_FOUND");
                    return new ResourceNotFoundException("Document not found: " + documentId);
                });
        return authorizeDocument(document, username, requiredPermission);
    }

    /**
     * Retrieves and locks a document using a pessimistic write lock (SELECT ... FOR UPDATE),
     * strictly evaluating authorization under the acquired lock in the current transaction.
     *
     * @param documentId         the document ID to retrieve and lock
     * @param username           the authenticated username requesting access
     * @param requiredPermission the minimum required permission (READ or EDIT)
     * @return the locked and authorized Document entity
     * @throws ResourceNotFoundException if document is not found or caller has no discovery rights (404)
     * @throws AccessDeniedException     if caller is an existing grantee lacking the required permission (403)
     */
    public Document getAuthorizedDocumentForUpdate(Long documentId, String username, SharePermission requiredPermission) {
        Objects.requireNonNull(documentId, "Document ID must not be null");
        Document document = documentRepository.findByIdForUpdate(documentId)
                .orElseThrow(() -> {
                    auditSecurityDenial(username, documentId, null, null, null, "reason=NOT_FOUND");
                    return new ResourceNotFoundException("Document not found: " + documentId);
                });
        return authorizeDocument(document, username, requiredPermission);
    }

    /**
     * Evaluates authorization on an already-loaded (or locked) Document entity.
     *
     * @param document           the Document entity to authorize
     * @param username           the authenticated username requesting access
     * @param requiredPermission the minimum required permission (READ or EDIT)
     * @return the authorized Document entity
     */
    public Document authorizeDocument(Document document, String username, SharePermission requiredPermission) {
        Objects.requireNonNull(document, "Document must not be null");
        Objects.requireNonNull(username, "Username must not be null");

        String normalizedUsername = username.trim();

        // 1. Verify caller user exists and is active (enabled)
        User requestingUser = userRepository.findByUsername(normalizedUsername)
                .orElseThrow(() -> {
                    auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=USER_NOT_FOUND");
                    return new ResourceNotFoundException("Document not found: " + document.getId());
                });

        if (!requestingUser.isEnabled()) {
            log.warn("Access rejected: account '{}' is disabled", normalizedUsername);
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=ACCOUNT_DISABLED");
            throw new ResourceNotFoundException("Document not found: " + document.getId());
        }

        // 2. Policy: when a document owner is disabled, their documents are unavailable to grantees
        if (!document.getOwner().isEnabled()) {
            log.warn("Access rejected (404): owner of document '{}' is disabled", document.getId());
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=OWNER_ACCOUNT_DISABLED");
            throw new ResourceNotFoundException("Document not found: " + document.getId());
        }

        // 3. Document owner has full authorization
        if (document.getOwner().getUsername().equalsIgnoreCase(normalizedUsername)) {
            return document;
        }

        // 4. Non-owner: check share grants
        Optional<DocumentShare> shareOpt = documentShareRepository.findByDocumentIdAndGranteeUsername(document.getId(), normalizedUsername);

        if (shareOpt.isEmpty()) {
            // Unshared user: Return 404 to avoid leaking document existence to unauthorized callers (anti-IDOR)
            log.warn("Authorization rejected (404): user '{}' has no grant for document '{}'", normalizedUsername, document.getId());
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=NOT_FOUND_OR_UNAUTHORIZED");
            throw new ResourceNotFoundException("Document not found: " + document.getId());
        }

        DocumentShare share = shareOpt.get();
        SharePermission grantedPermission = share.getPermission();

        // 5. Evaluate required permission
        if (requiredPermission == null || requiredPermission == SharePermission.READ) {
            if (grantedPermission.allowsRead()) {
                return document;
            }
        } else if (requiredPermission == SharePermission.EDIT) {
            if (grantedPermission.allowsEdit()) {
                return document;
            }
            // Grantee has READ but attempted EDIT: Return 403 because they already know document exists
            log.warn("Authorization denied (403): user '{}' has READ permission but requested EDIT on document '{}'", normalizedUsername, document.getId());
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=INSUFFICIENT_PERMISSION");
            throw new AccessDeniedException("Insufficient permission to modify document: " + document.getId());
        }

        auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=INSUFFICIENT_PERMISSION");
        throw new AccessDeniedException("Insufficient permission for requested document operation");
    }

    /**
     * Retrieves a document strictly verifying that the caller is the document OWNER (read-only lookup).
     *
     * @param documentId the document ID
     * @param username   the authenticated username
     * @return the Document entity if caller is owner
     * @throws ResourceNotFoundException if document is not found or caller has no discovery rights (404)
     * @throws AccessDeniedException     if caller is an existing grantee attempting an owner-only action (403)
     */
    public Document getAuthorizedDocumentForOwner(Long documentId, String username) {
        Objects.requireNonNull(documentId, "Document ID must not be null");
        Document document = documentRepository.findById(documentId)
                .orElseThrow(() -> {
                    auditSecurityDenial(username, documentId, null, null, null, "reason=NOT_FOUND");
                    return new ResourceNotFoundException("Document not found: " + documentId);
                });
        return authorizeDocumentForOwner(document, username);
    }

    /**
     * Retrieves and locks a document using a pessimistic write lock (SELECT ... FOR UPDATE),
     * strictly verifying that the caller is the document OWNER under the acquired lock.
     * Required for owner-only modifying operations: document deletion and share management.
     *
     * @param documentId the document ID to lock and authorize
     * @param username   the authenticated username
     * @return the locked Document entity if caller is owner
     * @throws ResourceNotFoundException if document is not found or caller has no discovery rights (404)
     * @throws AccessDeniedException     if caller is an existing grantee attempting an owner-only action (403)
     */
    public Document getAuthorizedDocumentForOwnerForUpdate(Long documentId, String username) {
        Objects.requireNonNull(documentId, "Document ID must not be null");
        Document document = documentRepository.findByIdForUpdate(documentId)
                .orElseThrow(() -> {
                    auditSecurityDenial(username, documentId, null, null, null, "reason=NOT_FOUND");
                    return new ResourceNotFoundException("Document not found: " + documentId);
                });
        return authorizeDocumentForOwner(document, username);
    }

    /**
     * Evaluates owner authorization on an already-loaded (or locked) Document entity.
     *
     * @param document the Document entity to authorize
     * @param username the authenticated username
     * @return the Document entity if caller is owner
     */
    public Document authorizeDocumentForOwner(Document document, String username) {
        Objects.requireNonNull(document, "Document must not be null");
        Objects.requireNonNull(username, "Username must not be null");

        String normalizedUsername = username.trim();

        User requestingUser = userRepository.findByUsername(normalizedUsername)
                .orElseThrow(() -> {
                    auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=USER_NOT_FOUND");
                    return new ResourceNotFoundException("Document not found: " + document.getId());
                });

        if (!requestingUser.isEnabled()) {
            log.warn("Owner operation rejected: account '{}' is disabled", normalizedUsername);
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=ACCOUNT_DISABLED");
            throw new ResourceNotFoundException("Document not found: " + document.getId());
        }

        if (!document.getOwner().isEnabled()) {
            log.warn("Owner operation rejected: document owner is disabled for document '{}'", document.getId());
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=OWNER_ACCOUNT_DISABLED");
            throw new ResourceNotFoundException("Document not found: " + document.getId());
        }

        // Caller is the owner
        if (document.getOwner().getUsername().equalsIgnoreCase(normalizedUsername)) {
            return document;
        }

        // Caller is NOT owner: check if they have a share grant
        boolean hasShareGrant = documentShareRepository.existsByDocumentIdAndGranteeUsername(document.getId(), normalizedUsername);

        if (hasShareGrant) {
            // Known grantee attempting owner-only action (delete, grant, revoke, list shares) -> 403 Forbidden
            log.warn("Access denied (403): grantee '{}' attempted owner-only operation on document '{}'", normalizedUsername, document.getId());
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=OWNER_ONLY_OPERATION");
            throw new AccessDeniedException("Only the document owner can perform this operation on document: " + document.getId());
        } else {
            // Unshared user attempting access -> 404 Not Found (anti-enumeration)
            log.warn("Authorization rejected (404): user '{}' has no grant on document '{}'", normalizedUsername, document.getId());
            auditSecurityDenial(normalizedUsername, document.getId(), document.getStorageKey(), null, null, "reason=NOT_FOUND_OR_UNAUTHORIZED");
            throw new ResourceNotFoundException("Document not found: " + document.getId());
        }
    }

    /**
     * Safely audits a security denial through the injected AuditService Spring proxy.
     *
     * <p>Connection-Pool Limitation:
     * {@code recordSecurityDenial()} runs with {@code Propagation.REQUIRES_NEW}, which suspends
     * the active transaction while keeping its database connection pinned to the current thread.
     * If HikariCP has insufficient connections under high concurrency, connection acquisition may
     * fail or block. To guarantee that audit failures NEVER mask, alter, or replace the primary
     * authorization decision, all exceptions are caught defensively here at the boundary.
     */
    private void auditSecurityDenial(
            String username,
            Long documentId,
            UUID documentStorageKey,
            String targetUsername,
            String clientIp,
            String reason) {
        if (auditService == null) {
            return;
        }
        try {
            auditService.recordSecurityDenial(username, documentId, documentStorageKey, targetUsername, clientIp, reason);
        } catch (Exception ex) {
            log.error("Failed to audit security denial for user '{}' on document {}: {}",
                    username, documentId, ex.getMessage());
        }
    }
}
