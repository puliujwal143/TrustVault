package com.trustvault.service;

import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.exception.ResourceNotFoundException;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Business service managing document sharing permissions.
 *
 * Security Requirements Enforced:
 * 1. ONLY the document owner may grant, update, list, or revoke shares. Grantees (including EDIT)
 *    cannot manage shares.
 * 2. Owners cannot grant access to themselves (rejected as an invalid operation).
 * 3. Non-existent recipient users are rejected safely with validation errors.
 * 4. Grants cannot be assigned to disabled user accounts.
 * 5. Re-granting updates the existing share row in-place (READ <-> EDIT), preserving the
 *    database unique constraint on (document_id, grantee_id) and preventing duplicate rows.
 * 6. Revoking a grant immediately stops authorizing subsequent requests.
 * 7. Pessimistic write locking on Document coordinates concurrent share grants and in-flight edits.
 */
@Service
@Transactional
public class DocumentShareService {

    private static final Logger log = LoggerFactory.getLogger(DocumentShareService.class);

    private final DocumentShareRepository documentShareRepository;
    private final UserRepository userRepository;
    private final DocumentAuthorizationService authorizationService;

    public DocumentShareService(
            DocumentShareRepository documentShareRepository,
            UserRepository userRepository,
            DocumentAuthorizationService authorizationService) {
        this.documentShareRepository = documentShareRepository;
        this.userRepository = userRepository;
        this.authorizationService = authorizationService;
    }

    /**
     * Grants or updates access to a document for a named user.
     * Coordinates with concurrent grant requests by acquiring a pessimistic write lock on the document.
     *
     * @param documentId      the document ID
     * @param granteeUsername the recipient's username
     * @param permission      the permission level to grant (READ or EDIT)
     * @param ownerUsername   the authenticated username of the document owner
     * @return the persisted DocumentShare entity
     * @throws IllegalArgumentException if grantee is owner, does not exist, is disabled, or inputs are invalid
     * @throws ResourceNotFoundException if document is not found or caller has no discovery rights (404)
     * @throws org.springframework.security.access.AccessDeniedException if caller is not the owner (403)
     */
    public DocumentShare grantAccess(Long documentId, String granteeUsername, SharePermission permission, String ownerUsername) {
        Objects.requireNonNull(permission, "Permission must not be null");
        Objects.requireNonNull(granteeUsername, "Grantee username must not be null");
        Objects.requireNonNull(ownerUsername, "Owner username must not be null");

        // 1. Lock document row and verify caller is document owner strictly under the acquired lock
        Document document = authorizationService.getAuthorizedDocumentForOwnerForUpdate(documentId, ownerUsername);

        String normalizedGrantee = granteeUsername.trim();
        String normalizedOwner = ownerUsername.trim();

        // 2. Reject self-granting
        if (normalizedGrantee.equalsIgnoreCase(normalizedOwner)) {
            throw new IllegalArgumentException("Document owners cannot grant access to themselves");
        }

        // 3. Look up grantee user and verify account is enabled
        User grantee = userRepository.findByUsername(normalizedGrantee)
                .orElseThrow(() -> new IllegalArgumentException("Grantee user not found: " + normalizedGrantee));

        if (!grantee.isEnabled()) {
            throw new IllegalArgumentException("Cannot grant access to disabled user: " + normalizedGrantee);
        }

        // 4. Upsert grant: update permission if share exists, otherwise create new record
        Optional<DocumentShare> existingShareOpt = documentShareRepository.findByDocumentIdAndGranteeUsername(documentId, grantee.getUsername());

        DocumentShare shareToSave;
        if (existingShareOpt.isPresent()) {
            shareToSave = existingShareOpt.get();
            shareToSave.setPermission(permission);
            log.info("Updated existing share grant for user '{}' on document '{}' to '{}'", normalizedGrantee, documentId, permission);
        } else {
            shareToSave = new DocumentShare(document, grantee, permission);
            log.info("Created new share grant for user '{}' on document '{}' with permission '{}'", normalizedGrantee, documentId, permission);
        }

        return documentShareRepository.save(shareToSave);
    }

    /**
     * Revokes access for a specific grantee, strictly verifying that the caller is the OWNER.
     * Coordinates with in-flight edits by acquiring a pessimistic write lock on the document before owner check and deletion.
     *
     * @param documentId      the document ID
     * @param granteeUsername the username whose grant should be revoked
     * @param ownerUsername   the authenticated username of the document owner
     * @throws ResourceNotFoundException if document or active share grant does not exist
     */
    public void revokeAccess(Long documentId, String granteeUsername, String ownerUsername) {
        Objects.requireNonNull(granteeUsername, "Grantee username must not be null");
        Objects.requireNonNull(ownerUsername, "Owner username must not be null");

        // 1. Lock document row and verify caller is document owner strictly under the acquired lock
        authorizationService.getAuthorizedDocumentForOwnerForUpdate(documentId, ownerUsername);

        String normalizedGrantee = granteeUsername.trim();

        // 2. Locate active grant
        DocumentShare share = documentShareRepository.findByDocumentIdAndGranteeUsername(documentId, normalizedGrantee)
                .orElseThrow(() -> new ResourceNotFoundException("No active share grant found for user: " + normalizedGrantee));

        // 3. Delete share record immediately
        documentShareRepository.delete(share);
        log.info("Revoked share grant for user '{}' on document '{}' by owner '{}'", normalizedGrantee, documentId, ownerUsername);
    }

    /**
     * Lists all active share grants for a document, strictly verifying that the caller is the OWNER.
     *
     * @param documentId    the document ID
     * @param ownerUsername the authenticated username of the document owner
     * @return list of active DocumentShare records
     */
    @Transactional(readOnly = true)
    public List<DocumentShare> listShares(Long documentId, String ownerUsername) {
        authorizationService.getAuthorizedDocumentForOwner(documentId, ownerUsername);
        return documentShareRepository.findByDocumentId(documentId);
    }
}
