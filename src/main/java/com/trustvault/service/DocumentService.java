package com.trustvault.service;

import com.trustvault.audit.AuditAction;
import com.trustvault.entity.Document;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.exception.ResourceNotFoundException;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.storage.FileValidationException;
import com.trustvault.storage.FileValidationService;
import com.trustvault.storage.StorageException;
import com.trustvault.storage.StorageService;
import com.trustvault.storage.ValidatedFileMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

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
 * 6. Emits structured audit events on document creation, read, update, and deletion within the
 *    same transaction.
 */
@Service
@Transactional(rollbackFor = Exception.class)
public class DocumentService {

    private static final Logger log = LoggerFactory.getLogger(DocumentService.class);

    private final DocumentRepository documentRepository;
    private final UserRepository userRepository;
    private final DocumentAuthorizationService authorizationService;
    private final AuditService auditService;
    private final StorageService storageService;
    private final FileValidationService fileValidationService;

    public DocumentService(
            DocumentRepository documentRepository,
            UserRepository userRepository,
            DocumentAuthorizationService authorizationService) {
        this(documentRepository, userRepository, authorizationService, null, null, null);
    }

    public DocumentService(
            DocumentRepository documentRepository,
            UserRepository userRepository,
            DocumentAuthorizationService authorizationService,
            AuditService auditService) {
        this(documentRepository, userRepository, authorizationService, auditService, null, null);
    }

    @Autowired
    public DocumentService(
            DocumentRepository documentRepository,
            UserRepository userRepository,
            DocumentAuthorizationService authorizationService,
            AuditService auditService,
            StorageService storageService,
            FileValidationService fileValidationService) {
        this.documentRepository = documentRepository;
        this.userRepository = userRepository;
        this.authorizationService = authorizationService;
        this.auditService = auditService;
        this.storageService = storageService;
        this.fileValidationService = fileValidationService;
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

        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.DOCUMENT_CREATE,
                    normalizedOwner,
                    savedDocument.getId(),
                    savedDocument.getStorageKey(),
                    null,
                    null,
                    null
            );
        }

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
        Document document = authorizationService.getAuthorizedDocument(documentId, requestingUsername, SharePermission.READ);
        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.DOCUMENT_READ,
                    requestingUsername != null ? requestingUsername.trim() : null,
                    document.getId(),
                    document.getStorageKey(),
                    null,
                    null,
                    null
            );
        }
        return document;
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

        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.DOCUMENT_UPDATE,
                    requestingUsername.trim(),
                    updatedDocument.getId(),
                    updatedDocument.getStorageKey(),
                    null,
                    null,
                    null
            );
        }

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
        Long docId = document.getId();
        UUID storageKey = document.getStorageKey();

        documentRepository.delete(document);

        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.DOCUMENT_DELETE,
                    requestingUsername.trim(),
                    docId,
                    storageKey,
                    null,
                    null,
                    null
            );
        }

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

    /**
     * Securely validates, stores, and attaches an uploaded file payload to an existing document.
     *
     * <p>Enforces atomic replacement and transaction boundary isolation:
     * <ol>
     *   <li>Validates the incoming file stream/content in-memory against size, signature, and format policies
     *       before persisting any data to disk.</li>
     *   <li>Generates an immutable, non-predictable UUID ({@code newFileStorageKey}) for the physical blob.
     *       Never trusts or accepts client-supplied storage keys.</li>
     *   <li>Registers transaction synchronization for rollback cleanup: if the database transaction aborts
     *       or rolls back for any reason, {@code newFileStorageKey} is immediately purged from storage.</li>
     *   <li>Persists validated bytes under {@code newFileStorageKey}. Existing files are never overwritten in-place.</li>
     *   <li>Acquires a pessimistic write lock (SELECT ... FOR UPDATE) and evaluates authorization: caller must be
     *       the document OWNER or hold an active {@link SharePermission#EDIT} grant.</li>
     *   <li>Captures {@code oldFileStorageKey} (null for initial upload, non-null for replacements).</li>
     *   <li>Mutates file metadata atomically and persists document state.</li>
     *   <li>Records {@link AuditAction#FILE_UPLOAD} success within the same database transaction
     *       ({@code Propagation.REQUIRED}).</li>
     *   <li>Registers transaction synchronization for commit cleanup: once the database transaction successfully
     *       commits, {@code oldFileStorageKey} is deleted from private storage. Failure during post-commit deletion
     *       is logged at ERROR level but does NOT invalidate the committed transaction.</li>
     * </ol>
     *
     * <p><b>Transaction & Crash Failure Semantics:</b>
     * <ul>
     *   <li><i>Storage failure before DB mutation:</i> Operation terminates; no database changes or audit records occur.</li>
     *   <li><i>Database failure/rollback after blob write:</i> Rollback synchronization purges {@code newFileStorageKey};
     *       previous file and metadata remain untouched.</li>
     *   <li><i>Crash after blob creation before commit:</i> Transaction aborts in PostgreSQL; new blob becomes an orphan
     *       while existing document state remains consistent.</li>
     *   <li><i>Crash after commit before old blob deletion:</i> Document correctly serves new blob; old blob remains on disk
     *       as an orphan without risking data loss.</li>
     * </ul>
     *
     * @param documentId          the document ID to attach the file to (required)
     * @param inputStream         incoming file data stream (required)
     * @param originalFilename    original client-supplied filename (required)
     * @param declaredContentType client-declared MIME content type (optional)
     * @param declaredSize        client-declared size in bytes (optional)
     * @param requestingUsername  authenticated username requesting the upload (required)
     * @param clientIp            client IP address for audit trail (optional)
     * @return the updated Document entity
     * @throws FileValidationException   if the file payload fails security validation
     * @throws ResourceNotFoundException if the document does not exist or caller has no access rights (404 anti-IDOR)
     * @throws AccessDeniedException     if caller lacks EDIT permission (e.g. READ-only grantee) (403)
     * @throws StorageException          if filesystem storage operations fail
     */
    public Document uploadFile(
            Long documentId,
            InputStream inputStream,
            String originalFilename,
            String declaredContentType,
            Long declaredSize,
            String requestingUsername,
            String clientIp) {

        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()) {
            throw new IllegalStateException("Secure file upload requires an active transaction synchronization context");
        }

        Objects.requireNonNull(documentId, "Document ID must not be null");
        Objects.requireNonNull(requestingUsername, "Requesting username must not be null");
        Objects.requireNonNull(inputStream, "Input stream must not be null");

        if (fileValidationService == null || storageService == null) {
            throw new IllegalStateException("FileValidationService and StorageService must be configured in DocumentService");
        }

        // 1. Validate file before storage (in-memory parsing, bounded streaming, signature checks)
        ValidatedFileMetadata validated = fileValidationService.validate(
                inputStream, originalFilename, declaredContentType, declaredSize
        );

        // 2. Generate a fresh, server-controlled UUID for the new physical blob
        UUID newFileStorageKey = UUID.randomUUID();

        // 3. Register rollback cleanup hook BEFORE storing so any subsequent failure purges the new blob
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == STATUS_ROLLED_BACK) {
                    try {
                        storageService.delete(newFileStorageKey);
                        log.info("Purged uncommitted file blob {} following transaction rollback", newFileStorageKey);
                    } catch (Exception e) {
                        log.warn("Failed to purge uncommitted file blob {} on rollback: {}", newFileStorageKey, e.getMessage(), e);
                    }
                }
            }
        });

        // 4. Store validated bytes under new key (never overwrites the current blob)
        storageService.store(newFileStorageKey, validated.openStream());

        // 5. Acquire document lock and authorize using existing rules with SharePermission.EDIT
        Document document = authorizationService.getAuthorizedDocumentForUpdate(
                documentId, requestingUsername, SharePermission.EDIT
        );

        // 6. Capture the previous fileStorageKey
        UUID oldFileStorageKey = document.getFileStorageKey();

        // 7. Update file metadata and the new fileStorageKey atomically
        document.setFileMetadata(
                newFileStorageKey,
                validated.originalFilename(),
                validated.contentType(),
                validated.size(),
                validated.checksum(),
                Instant.now()
        );

        Document savedDocument = documentRepository.save(document);

        // 8. Record FILE_UPLOAD success in the same database transaction as the metadata change
        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.FILE_UPLOAD,
                    requestingUsername.trim(),
                    savedDocument.getId(),
                    savedDocument.getStorageKey(),
                    null,
                    clientIp,
                    String.format(Locale.ROOT, "filename=%s,size=%d,mime=%s",
                            validated.originalFilename(), validated.size(), validated.contentType())
            );
        }

        // 9. After transaction commit, delete the previous blob if one exists
        if (oldFileStorageKey != null) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    try {
                        storageService.delete(oldFileStorageKey);
                        log.info("Successfully deleted superseded file blob {} after commit", oldFileStorageKey);
                    } catch (Exception e) {
                        // Non-fatal to committed transaction: log error for operator/cleanup job
                        log.error("Failed to delete superseded file blob {} after commit: {}", oldFileStorageKey, e.getMessage(), e);
                    }
                }
            });
        }

        log.info("File '{}' (size: {} bytes, blob: {}) successfully uploaded to document {} by '{}'",
                validated.originalFilename(), validated.size(), newFileStorageKey, savedDocument.getId(), requestingUsername);

        return savedDocument;
    }

    /**
     * Multipart upload convenience overload.
     */
    public Document uploadFile(
            Long documentId,
            MultipartFile file,
            String requestingUsername,
            String clientIp) {

        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()) {
            throw new IllegalStateException("Secure file upload requires an active transaction synchronization context");
        }

        if (file == null) {
            throw new FileValidationException("Upload file payload must not be null");
        }
        try (InputStream inputStream = file.getInputStream()) {
            return uploadFile(
                    documentId,
                    inputStream,
                    file.getOriginalFilename(),
                    file.getContentType(),
                    file.getSize(),
                    requestingUsername,
                    clientIp
            );
        } catch (IOException e) {
            throw new FileValidationException("Failed to read upload file stream: " + e.getMessage(), e);
        }
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
