package com.trustvault.service;

import com.trustvault.entity.Document;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.exception.ResourceNotFoundException;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Business service managing document metadata operations and ownership lifecycle.
 *
 * Security Requirements Enforced:
 * 1. Owner is ALWAYS resolved from the database via the authenticated username; client-supplied
 *    owner IDs are never trusted or accepted.
 * 2. Every retrieve, update, and delete operation enforces document-level authorization via
 *    DocumentAuthorizationService.
 * 3. Title and description length constraints are validated proactively before persistence.
 * 4. List operations strictly isolate query results to documents owned by or explicitly shared
 *    with the requesting user.
 * 5. Uses Spring declarative transaction boundaries (@Transactional).
 */
@Service
@Transactional
public class DocumentService {

    private static final Logger log = LoggerFactory.getLogger(DocumentService.class);

    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;
    private final DocumentAuthorizationService authorizationService;

    public DocumentService(
            DocumentRepository documentRepository,
            UserRepository userRepository,
            DocumentAuthorizationService authorizationService) {
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
        this.authorizationService = authorizationService;
    }

    /**
     * Creates and persists a new document, assigning the authenticated user as the exclusive owner.
     *
     * @param title          document title (1-255 characters, required)
     * @param description    optional description (max 1000 characters)
     * @param ownerUsername  the authenticated username of the creator
     * @return the persisted Document entity
     * @throws IllegalArgumentException if title or owner parameters are invalid
     * @throws IllegalStateException    if owner user account is disabled
     */
    public Document createDocument(String title, String description, String ownerUsername) {
        Objects.requireNonNull(ownerUsername, "Owner username must not be null");

        String normalizedOwner = ownerUsername.trim();
        User owner = userRepository.findByUsername(normalizedOwner)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + normalizedOwner));

        if (!owner.isEnabled()) {
            throw new IllegalStateException("Disabled account cannot create documents: " + normalizedOwner);
        }

        String validatedTitle = validateAndSanitizeTitle(title);
        String validatedDescription = validateAndSanitizeDescription(description);

        Document document = new Document(validatedTitle, validatedDescription, owner);
        Document savedDocument = documentRepository.save(document);

        log.info("Document '{}' (ID: {}) created by user '{}'", savedDocument.getTitle(), savedDocument.getId(), normalizedOwner);
        return savedDocument;
    }

    /**
     * Retrieves document metadata, verifying that the caller has READ access (as owner or grantee).
     *
     * @param documentId         the document ID
     * @param requestingUsername the authenticated username
     * @return the Document entity
     */
    @Transactional(readOnly = true)
    public Document getDocument(Long documentId, String requestingUsername) {
        return authorizationService.getAuthorizedDocument(documentId, requestingUsername, SharePermission.READ);
    }

    /**
     * Updates document metadata, verifying that the caller has EDIT access (as owner or EDIT grantee).
     * Coordinates with share management by acquiring a pessimistic write lock on the document.
     *
     * @param documentId         the document ID
     * @param newTitle           the updated title (1-255 characters)
     * @param newDescription     the updated description (max 1000 characters)
     * @param requestingUsername the authenticated username
     * @return the updated Document entity
     */
    public Document updateDocument(Long documentId, String newTitle, String newDescription, String requestingUsername) {
        Objects.requireNonNull(documentId, "Document ID must not be null");
        Objects.requireNonNull(requestingUsername, "Requesting username must not be null");

        // 1. Lock document and authorize EDIT permission under the acquired lock in the current transaction
        Document document = authorizationService.getAuthorizedDocumentForUpdate(documentId, requestingUsername, SharePermission.EDIT);

        String validatedTitle = validateAndSanitizeTitle(newTitle);
        String validatedDescription = validateAndSanitizeDescription(newDescription);

        document.setTitle(validatedTitle);
        document.setDescription(validatedDescription);

        Document updatedDocument = documentRepository.save(document);
        log.info("Document '{}' (ID: {}) updated by user '{}'", updatedDocument.getTitle(), updatedDocument.getId(), requestingUsername);
        return updatedDocument;
    }

    /**
     * Deletes a document and cascades share deletions, strictly verifying that the caller is the OWNER.
     * Coordinates with concurrent operations by locking the document row before owner authorization and deletion.
     *
     * @param documentId         the document ID
     * @param requestingUsername the authenticated username
     */
    public void deleteDocument(Long documentId, String requestingUsername) {
        Objects.requireNonNull(documentId, "Document ID must not be null");
        Objects.requireNonNull(requestingUsername, "Requesting username must not be null");

        // Lock document and authorize owner under the acquired lock, then delete the locked document entity
        Document document = authorizationService.getAuthorizedDocumentForOwnerForUpdate(documentId, requestingUsername);

        documentRepository.delete(document);
        log.info("Document '{}' (ID: {}) deleted by owner '{}'", document.getTitle(), document.getId(), requestingUsername);
    }

    /**
     * Lists all documents accessible to the requesting user (owned or shared).
     *
     * @param requestingUsername the authenticated username
     * @return list of accessible documents ordered by updated timestamp
     */
    @Transactional(readOnly = true)
    public List<Document> listAccessibleDocuments(String requestingUsername) {
        if (requestingUsername == null || requestingUsername.isBlank()) {
            return Collections.emptyList();
        }

        String normalizedUsername = requestingUsername.trim();
        boolean userActive = userRepository.findByUsername(normalizedUsername)
                .map(User::isEnabled)
                .orElse(false);

        if (!userActive) {
            return Collections.emptyList();
        }

        return documentRepository.findAllAccessibleByUsername(normalizedUsername);
    }

    private String validateAndSanitizeTitle(String title) {
        if (title == null || title.trim().isBlank()) {
            throw new IllegalArgumentException("Document title must not be blank");
        }
        String trimmed = title.trim();
        if (trimmed.length() > 255) {
            throw new IllegalArgumentException("Document title must not exceed 255 characters");
        }
        return trimmed;
    }

    private String validateAndSanitizeDescription(String description) {
        if (description == null) {
            return null;
        }
        String trimmed = description.trim();
        if (trimmed.length() > 1000) {
            throw new IllegalArgumentException("Document description must not exceed 1000 characters");
        }
        return trimmed.isEmpty() ? null : trimmed;
    }
}
