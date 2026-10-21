package com.trustvault.service;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
import com.trustvault.entity.Document;
import com.trustvault.entity.Role;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.exception.ResourceNotFoundException;
import com.trustvault.repository.AuditEventRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.storage.FileValidationException;
import com.trustvault.storage.FileValidationService;
import com.trustvault.storage.StorageException;
import com.trustvault.storage.StorageService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

/**
 * Service-level integration tests for secure file uploading in {@link DocumentService}.
 *
 * Verifies:
 * - Initial upload success for document owner.
 * - Successful replacement of existing file, verifying old-blob deletion after commit.
 * - Failed replacement preserves previous file blob and previous metadata.
 * - Storage write failures abort the transaction cleanly without database mutation.
 * - Database rollback purges the newly written blob without touching the old blob.
 * - EDIT collaborator upload permission.
 * - READ collaborator access denial (403) and unshared user denial (404 anti-IDOR).
 * - Audit event generation: FILE_UPLOAD SUCCESS in the same transaction, and ACCESS_DENIED on denial.
 * - Old-blob deletion failure after commit does not invalidate the committed database transaction.
 */
@SpringBootTest
class DocumentFileUploadServiceTest {

    @Autowired
    private DocumentService documentService;

    @Autowired
    private DocumentShareService documentShareService;

    @Autowired
    private UserService userService;

    @Autowired
    private StorageService storageService;

    @Autowired
    private FileValidationService fileValidationService;

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private DocumentShareRepository documentShareRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private AuditService auditService;

    @Autowired
    private DocumentAuthorizationService documentAuthorizationService;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private User alice;
    private User bob;
    private User carol;
    private User mallory;
    private User admin;

    private static final byte[] VALID_PDF = "%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VALID_PNG = new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D, 0x49, 0x48, 0x44, 0x52
    };
    private static final byte[] VALID_TXT = "TrustVault Secure Plaintext Content".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        cleanup();
        alice = userService.createUser("alice", "Password123!", "alice@example.com", Role.ROLE_USER);
        bob = userService.createUser("bob", "Password123!", "bob@example.com", Role.ROLE_USER);
        carol = userService.createUser("carol", "Password123!", "carol@example.com", Role.ROLE_USER);
        mallory = userService.createUser("mallory", "Password123!", "mallory@example.com", Role.ROLE_USER);
        admin = userService.createUser("admin", "Password123!", "admin@example.com", Role.ROLE_ADMIN);
        jdbcTemplate.execute("DELETE FROM audit_events");
    }

    @AfterEach
    void tearDown() {
        cleanup();
    }

    private void cleanup() {
        jdbcTemplate.execute("DELETE FROM audit_events");
        documentShareRepository.deleteAll();
        documentRepository.deleteAll();
        userRepository.deleteAll();
        storageService.deleteAll();
    }

    @Nested
    @DisplayName("1. Successful Upload Workflows")
    class SuccessfulUploadTests {

        @Test
        @DisplayName("uploadFile: initial upload succeeds for document owner and stores physical blob")
        void testInitialUploadSuccess() {
            Document doc = documentService.createDocument("Owner Document", "Description", "alice");
            Long docId = doc.getId();

            Document uploaded = documentService.uploadFile(
                    docId,
                    new ByteArrayInputStream(VALID_PDF),
                    "annual_report.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "192.168.1.100"
            );

            assertThat(uploaded.hasFile()).isTrue();
            assertThat(uploaded.getFileOriginalName()).isEqualTo("annual_report.pdf");
            assertThat(uploaded.getFileContentType()).isEqualTo("application/pdf");
            assertThat(uploaded.getFileSize()).isEqualTo((long) VALID_PDF.length);
            assertThat(uploaded.getFileChecksum()).isNotNull();
            assertThat(uploaded.getFileStorageKey()).isNotNull();
            assertThat(uploaded.getFileUploadedAt()).isNotNull();

            // Verify blob exists in physical storage
            UUID storageBlobKey = uploaded.getFileStorageKey();
            assertThat(storageService.exists(storageBlobKey)).isTrue();
            assertThat(storageService.getFileSize(storageBlobKey)).isEqualTo(VALID_PDF.length);

            // Verify audit event in same transaction
            List<AuditEvent> audits = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
            AuditEvent uploadAudit = audits.stream()
                    .filter(a -> a.getAction() == AuditAction.FILE_UPLOAD)
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Expected FILE_UPLOAD audit event"));

            assertThat(uploadAudit.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
            assertThat(uploadAudit.getDocumentId()).isEqualTo(docId);
            assertThat(uploadAudit.getClientIp()).isEqualTo("192.168.1.100");
            assertThat(uploadAudit.getDetails()).contains("filename=annual_report.pdf");
        }

        @Test
        @DisplayName("uploadFile: multipart convenience overload succeeds")
        void testMultipartUploadConvenience() {
            Document doc = documentService.createDocument("Multipart Doc", "Description", "alice");
            MockMultipartFile multipartFile = new MockMultipartFile(
                    "file",
                    "notes.txt",
                    "text/plain",
                    VALID_TXT
            );

            Document uploaded = documentService.uploadFile(doc.getId(), multipartFile, "alice", "10.0.0.1");

            assertThat(uploaded.hasFile()).isTrue();
            assertThat(uploaded.getFileOriginalName()).isEqualTo("notes.txt");
            assertThat(uploaded.getFileContentType()).isEqualTo("text/plain");
            assertThat(uploaded.getFileSize()).isEqualTo((long) VALID_TXT.length);
            assertThat(storageService.exists(uploaded.getFileStorageKey())).isTrue();
        }

        @Test
        @DisplayName("uploadFile: EDIT collaborator can successfully upload file")
        void testEditCollaboratorUpload() {
            Document doc = documentService.createDocument("Collab Doc", "Shared with Bob", "alice");
            documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

            Document uploaded = documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PNG),
                    "diagram.png",
                    "image/png",
                    (long) VALID_PNG.length,
                    "bob",
                    "192.168.1.50"
            );

            assertThat(uploaded.hasFile()).isTrue();
            assertThat(uploaded.getFileOriginalName()).isEqualTo("diagram.png");
            assertThat(storageService.exists(uploaded.getFileStorageKey())).isTrue();

            // Verify audit records Bob as actor
            List<AuditEvent> bobAudits = auditEventRepository.findByActorUsernameOrderByTimestampDesc("bob");
            assertThat(bobAudits).anyMatch(a -> a.getAction() == AuditAction.FILE_UPLOAD
                    && a.getOutcome() == AuditOutcome.SUCCESS
                    && a.getDocumentId().equals(doc.getId()));
        }

        @Test
        @DisplayName("uploadFile: successful replacement deletes old blob and activates new blob")
        void testSuccessfulReplacement() {
            Document doc = documentService.createDocument("Replace Doc", "Initial", "alice");
            Document initialUpload = documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "v1.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "127.0.0.1"
            );

            UUID oldBlobKey = initialUpload.getFileStorageKey();
            assertThat(storageService.exists(oldBlobKey)).isTrue();

            // Replace with v2 PNG
            Document replacement = documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PNG),
                    "v2.png",
                    "image/png",
                    (long) VALID_PNG.length,
                    "alice",
                    "127.0.0.1"
            );

            UUID newBlobKey = replacement.getFileStorageKey();
            assertThat(newBlobKey).isNotEqualTo(oldBlobKey);

            // New blob exists in storage
            assertThat(storageService.exists(newBlobKey)).isTrue();
            assertThat(replacement.getFileOriginalName()).isEqualTo("v2.png");

            // Old blob was deleted post-commit
            assertThat(storageService.exists(oldBlobKey)).isFalse();
        }

        @Test
        @DisplayName("uploadFile: old-blob deletion occurs only after transaction commit, preserving old blob during transaction")
        void testOldBlobDeletionOccursOnlyAfterCommit() {
            Document doc = documentService.createDocument("Replace Commit Order Doc", "Initial", "alice");
            Document initialUpload = documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "v1.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "127.0.0.1"
            );

            UUID oldBlobKey = initialUpload.getFileStorageKey();
            assertThat(storageService.exists(oldBlobKey)).isTrue();

            TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);
            final UUID[] newBlobKeyHolder = new UUID[1];

            txTemplate.execute(status -> {
                Document replacement = documentService.uploadFile(
                        doc.getId(),
                        new ByteArrayInputStream(VALID_PNG),
                        "v2.png",
                        "image/png",
                        (long) VALID_PNG.length,
                        "alice",
                        "127.0.0.1"
                );

                newBlobKeyHolder[0] = replacement.getFileStorageKey();
                assertThat(newBlobKeyHolder[0]).isNotEqualTo(oldBlobKey);

                // Before commit, BOTH old blob and new blob MUST exist simultaneously
                assertThat(storageService.exists(oldBlobKey)).isTrue();
                assertThat(storageService.exists(newBlobKeyHolder[0])).isTrue();

                return null;
            });

            // After transaction commit finishes:
            // 1. Old blob is now deleted post-commit
            assertThat(storageService.exists(oldBlobKey)).isFalse();
            // 2. New blob is preserved in storage
            assertThat(storageService.exists(newBlobKeyHolder[0])).isTrue();
        }
    }

    @Nested
    @DisplayName("2. Failure & Rollback Semantics")
    class FailureAndRollbackTests {

        @Test
        @DisplayName("uploadFile: validation failure preserves existing file blob and previous metadata")
        void testFailedReplacementValidationPreservesOldBlob() {
            Document doc = documentService.createDocument("Protected Doc", "Desc", "alice");
            Document initial = documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "v1.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "127.0.0.1"
            );
            UUID oldKey = initial.getFileStorageKey();
            assertThat(storageService.exists(oldKey)).isTrue();

            // Attempt invalid replacement (spoofed PDF with PNG content)
            assertThatThrownBy(() -> documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PNG),
                    "bad.pdf",
                    "application/pdf",
                    (long) VALID_PNG.length,
                    "alice",
                    "127.0.0.1"
            )).isInstanceOf(FileValidationException.class);

            // Old blob remains intact in storage and in database
            assertThat(storageService.exists(oldKey)).isTrue();
            Document current = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(current.getFileStorageKey()).isEqualTo(oldKey);
            assertThat(current.getFileOriginalName()).isEqualTo("v1.pdf");
        }

        @Test
        @DisplayName("uploadFile: storage write failure aborts without mutating document metadata")
        void testStorageWriteFailure() {
            Document doc = documentService.createDocument("Doc for Write Failure", "Desc", "alice");

            StorageService spyStorage = spy(storageService);
            doThrow(new StorageException("Simulated disk I/O write failure"))
                    .when(spyStorage).store(any(UUID.class), any(InputStream.class));

            DocumentService customService = new DocumentService(
                    documentRepository,
                    userRepository,
                    documentAuthorizationService,
                    auditService,
                    spyStorage,
                    fileValidationService
            );

            TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);

            assertThatThrownBy(() -> txTemplate.execute(status -> customService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "document.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "127.0.0.1"
            ))).isInstanceOf(StorageException.class).hasMessageContaining("Simulated disk I/O write failure");

            Document unchanged = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(unchanged.hasFile()).isFalse();

            // Verify no FILE_UPLOAD SUCCESS event was recorded
            List<AuditEvent> audits = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
            assertThat(audits).noneMatch(a -> a.getAction() == AuditAction.FILE_UPLOAD);
        }

        @Test
        @DisplayName("uploadFile: database transaction rollback purges new blob and preserves old blob")
        void testDatabaseRollbackPurgesNewBlob() {
            Document doc = documentService.createDocument("Rollback Doc", "Initial", "alice");
            Document initial = documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "v1.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "127.0.0.1"
            );
            UUID oldKey = initial.getFileStorageKey();
            assertThat(storageService.exists(oldKey)).isTrue();

            TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);

            final UUID[] capturedNewKey = new UUID[1];

            assertThatThrownBy(() -> txTemplate.execute(status -> {
                Document updated = documentService.uploadFile(
                        doc.getId(),
                        new ByteArrayInputStream(VALID_PNG),
                        "v2.png",
                        "image/png",
                        (long) VALID_PNG.length,
                        "alice",
                        "127.0.0.1"
                );
                capturedNewKey[0] = updated.getFileStorageKey();
                assertThat(storageService.exists(capturedNewKey[0])).isTrue();

                // Force deliberate transaction rollback
                throw new RuntimeException("Simulated database constraint or business rollback");
            })).isInstanceOf(RuntimeException.class).hasMessageContaining("Simulated database constraint");

            // Verifications:
            // 1. The newly written blob must have been purged by the rollback synchronization
            assertThat(capturedNewKey[0]).isNotNull();
            assertThat(storageService.exists(capturedNewKey[0])).isFalse();

            // 2. The old blob must still exist
            assertThat(storageService.exists(oldKey)).isTrue();

            // 3. Database state was rolled back to old file metadata
            Document reloaded = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(reloaded.getFileStorageKey()).isEqualTo(oldKey);
            assertThat(reloaded.getFileOriginalName()).isEqualTo("v1.pdf");
        }
    }

    @Nested
    @DisplayName("3. Authorization & Audit Access Control")
    class AuthorizationAndAuditTests {

        @Test
        @DisplayName("uploadFile: READ collaborator is denied (403) and ACCESS_DENIED is audited")
        void testReadCollaboratorDenied() {
            Document doc = documentService.createDocument("Read Only Doc", "Desc", "alice");
            documentShareService.grantAccess(doc.getId(), "carol", SharePermission.READ, "alice");

            assertThatThrownBy(() -> documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "unauthorized.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "carol",
                    "192.168.1.99"
            )).isInstanceOf(AccessDeniedException.class);

            // Document remains without file
            Document unchanged = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(unchanged.hasFile()).isFalse();

            // Denial was audited autonomously
            List<AuditEvent> denials = auditEventRepository.findByActorUsernameOrderByTimestampDesc("carol");
            assertThat(denials).anyMatch(a -> a.getAction() == AuditAction.ACCESS_DENIED
                    && a.getOutcome() == AuditOutcome.DENIED
                    && a.getDetails().contains("reason=INSUFFICIENT_PERMISSION"));
        }

        @Test
        @DisplayName("uploadFile: unshared user is denied with 404 anti-IDOR")
        void testUnsharedUserDeniedWith404() {
            Document doc = documentService.createDocument("Secret Doc", "Desc", "alice");

            assertThatThrownBy(() -> documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "probe.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "mallory",
                    "10.0.0.99"
            )).isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Document not found");

            // Document remains without file
            Document unchanged = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(unchanged.hasFile()).isFalse();

            // Denial was audited autonomously with anti-enumeration reason
            List<AuditEvent> denials = auditEventRepository.findByActorUsernameOrderByTimestampDesc("mallory");
            assertThat(denials).anyMatch(a -> a.getAction() == AuditAction.ACCESS_DENIED
                    && a.getOutcome() == AuditOutcome.DENIED
                    && a.getDetails().contains("reason=NOT_FOUND_OR_UNAUTHORIZED"));
        }

        @Test
        @DisplayName("uploadFile: ROLE_ADMIN without a share grant cannot upload and receives 404 anti-IDOR")
        void testAdminWithoutShareGrantDeniedWith404() throws Exception {
            // Alice creates a document with an initial file
            Document doc = documentService.createDocument("Alice Private Financials", "Restricted", "alice");
            Document initialUpload = documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "financials.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "192.168.1.10"
            );
            UUID initialBlobKey = initialUpload.getFileStorageKey();
            assertThat(storageService.exists(initialBlobKey)).isTrue();

            // Admin user attempts to upload to Alice's document without a grant
            assertThatThrownBy(() -> documentService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PNG),
                    "admin_override.png",
                    "image/png",
                    (long) VALID_PNG.length,
                    "admin",
                    "10.0.0.1"
            )).isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("Document not found");

            // Verify document metadata and original blob remain unchanged
            Document reloaded = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(reloaded.getFileStorageKey()).isEqualTo(initialBlobKey);
            assertThat(reloaded.getFileOriginalName()).isEqualTo("financials.pdf");
            assertThat(reloaded.getFileContentType()).isEqualTo("application/pdf");
            assertThat(reloaded.getFileSize()).isEqualTo((long) VALID_PDF.length);
            assertThat(storageService.exists(initialBlobKey)).isTrue();

            // Verify no new or orphaned blob remains in storage (only the initial blob exists)
            try (var stream = Files.list(storageService.resolvePath(initialBlobKey).getParent())) {
                assertThat(stream.toList()).containsExactly(storageService.resolvePath(initialBlobKey));
            }

            // Verify denial audit event was recorded with anti-enumeration reason
            List<AuditEvent> adminAudits = auditEventRepository.findByActorUsernameOrderByTimestampDesc("admin");
            assertThat(adminAudits).anyMatch(a -> a.getAction() == AuditAction.ACCESS_DENIED
                    && a.getOutcome() == AuditOutcome.DENIED
                    && a.getDetails().contains("reason=NOT_FOUND_OR_UNAUTHORIZED"));
        }
    }

    @Nested
    @DisplayName("4. Post-Commit Old Blob Deletion Failure Resilience")
    class PostCommitResilienceTests {

        @Test
        @DisplayName("uploadFile: failed old-blob deletion after commit does not invalidate committed transaction")
        void testOldBlobDeletionFailureDoesNotFailTransaction() {
            // Setup a spied storage service to simulate deletion failure
            StorageService spyStorage = spy(storageService);
            DocumentService customService = new DocumentService(
                    documentRepository,
                    userRepository,
                    documentAuthorizationService,
                    auditService,
                    spyStorage,
                    fileValidationService
            );

            TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);

            Document doc = documentService.createDocument("Resilience Doc", "Desc", "alice");
            Document initial = txTemplate.execute(status -> customService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "v1.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "127.0.0.1"
            ));
            assertThat(initial).isNotNull();
            UUID oldKey = initial.getFileStorageKey();

            // Force spy to throw on deleting oldKey
            doThrow(new StorageException("Simulated filesystem lock failure"))
                    .when(spyStorage).delete(oldKey);

            // Execute replacement under an active transaction
            Document replaced = txTemplate.execute(status -> customService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PNG),
                    "v2.png",
                    "image/png",
                    (long) VALID_PNG.length,
                    "alice",
                    "127.0.0.1"
            ));

            assertThat(replaced).isNotNull();
            assertThat(replaced.getFileOriginalName()).isEqualTo("v2.png");

            // Verify database transaction committed successfully despite the deletion failure
            Document committedDoc = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(committedDoc.getFileStorageKey()).isEqualTo(replaced.getFileStorageKey());
            assertThat(committedDoc.getFileOriginalName()).isEqualTo("v2.png");
        }
    }

    @Nested
    @DisplayName("5. Transaction Context Invariant Enforcement")
    class TransactionInvariantTests {

        @Test
        @DisplayName("uploadFile: stream upload fails immediately if invoked without active transaction synchronization")
        void testUploadStreamWithoutActiveTransactionFailsImmediately() throws Exception {
            DocumentService unproxiedService = new DocumentService(
                    documentRepository,
                    userRepository,
                    documentAuthorizationService,
                    auditService,
                    storageService,
                    fileValidationService
            );

            Document doc = documentService.createDocument("No Tx Stream Doc", "Desc", "alice");

            assertThatThrownBy(() -> unproxiedService.uploadFile(
                    doc.getId(),
                    new ByteArrayInputStream(VALID_PDF),
                    "document.pdf",
                    "application/pdf",
                    (long) VALID_PDF.length,
                    "alice",
                    "127.0.0.1"
            )).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Secure file upload requires an active transaction synchronization context");

            // Verify document metadata is untouched (hasFile remains false)
            Document reloaded = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(reloaded.hasFile()).isFalse();

            // Verify no file was created in storage
            try (var stream = Files.list(storageService.resolvePath(UUID.randomUUID()).getParent())) {
                assertThat(stream.toList()).isEmpty();
            }
        }

        @Test
        @DisplayName("uploadFile: multipart upload fails immediately if invoked without active transaction synchronization")
        void testUploadMultipartWithoutActiveTransactionFailsImmediately() throws Exception {
            DocumentService unproxiedService = new DocumentService(
                    documentRepository,
                    userRepository,
                    documentAuthorizationService,
                    auditService,
                    storageService,
                    fileValidationService
            );

            Document doc = documentService.createDocument("No Tx Multipart Doc", "Desc", "alice");
            MockMultipartFile multipartFile = new MockMultipartFile(
                    "file",
                    "document.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            assertThatThrownBy(() -> unproxiedService.uploadFile(
                    doc.getId(),
                    multipartFile,
                    "alice",
                    "127.0.0.1"
            )).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Secure file upload requires an active transaction synchronization context");

            // Verify document metadata is untouched (hasFile remains false)
            Document reloaded = documentRepository.findById(doc.getId()).orElseThrow();
            assertThat(reloaded.hasFile()).isFalse();

            // Verify no file was created in storage
            try (var stream = Files.list(storageService.resolvePath(UUID.randomUUID()).getParent())) {
                assertThat(stream.toList()).isEmpty();
            }
        }
    }
}
