package com.trustvault.repository;

import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.Role;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Persistence integration tests for Document and DocumentShare entities and repositories.
 *
 * Verifies:
 * - Document persistence, ownership mapping, UUID storageKey generation, and audit timestamps.
 * - DocumentShare persistence, permission mapping, and granted timestamp.
 * - Database unique constraint preventing duplicate (document_id, grantee_id) shares.
 * - Grant updates (switching READ to EDIT or vice versa on an existing share).
 * - JPA Set invariance for Document and DocumentShare across persist state transitions.
 * - Foreign key cascade deletion of document shares when a parent document is deleted.
 * - Accessible documents query returning owned and shared documents while excluding unshared ones.
 * - SharePermission hierarchy helper methods (READ vs EDIT).
 */
@SpringBootTest
class DocumentPersistenceTest {

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private DocumentShareRepository documentShareRepository;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        cleanup();
    }

    @AfterEach
    void tearDown() {
        cleanup();
    }

    private void cleanup() {
        documentShareRepository.deleteAll();
        documentRepository.deleteAll();
        userRepository.deleteAll();
    }

    private User persistUser(String username, String email) {
        User user = new User(username, "$2a$12$N9qo8uLOickgx2ZMRZoMye.I1z4mKjM97B8Z9e5K.sZz1mNqG9cK2", email, Role.ROLE_USER);
        return userRepository.saveAndFlush(user);
    }

    @Test
    @DisplayName("Document persistence: should persist document with valid owner, UUID storage key, and timestamps")
    void document_shouldPersistAndMapOwnerCorrectly() {
        User owner = persistUser("alice", "alice@example.com");

        Document doc = new Document("Financial Report 2026", "Confidential Q3 metrics", owner);
        Document savedDoc = documentRepository.saveAndFlush(doc);

        assertThat(savedDoc.getId()).isNotNull();
        assertThat(savedDoc.getStorageKey()).isNotNull();
        assertThat(savedDoc.getTitle()).isEqualTo("Financial Report 2026");
        assertThat(savedDoc.getDescription()).isEqualTo("Confidential Q3 metrics");
        assertThat(savedDoc.getOwner().getId()).isEqualTo(owner.getId());
        assertThat(savedDoc.getCreatedAt()).isNotNull();
        assertThat(savedDoc.getUpdatedAt()).isNotNull();

        // Verify retrieval by ID
        Optional<Document> fetched = documentRepository.findById(savedDoc.getId());
        assertThat(fetched).isPresent();
        assertThat(fetched.get().getTitle()).isEqualTo("Financial Report 2026");

        // Verify retrieval by UUID storage key
        Optional<Document> fetchedByUuid = documentRepository.findByStorageKey(savedDoc.getStorageKey());
        assertThat(fetchedByUuid).isPresent();
        assertThat(fetchedByUuid.get().getId()).isEqualTo(savedDoc.getId());
    }

    @Test
    @DisplayName("DocumentShare persistence: should link document to grantee with permission and grant timestamp")
    void documentShare_shouldPersistAndMapGranteeWithPermission() {
        User owner = persistUser("bob", "bob@example.com");
        User grantee = persistUser("carol", "carol@example.com");

        Document doc = documentRepository.saveAndFlush(new Document("Project Alpha Spec", "Architecture spec", owner));

        DocumentShare share = new DocumentShare(doc, grantee, SharePermission.READ);
        DocumentShare savedShare = documentShareRepository.saveAndFlush(share);

        assertThat(savedShare.getId()).isNotNull();
        assertThat(savedShare.getDocument().getId()).isEqualTo(doc.getId());
        assertThat(savedShare.getGrantee().getId()).isEqualTo(grantee.getId());
        assertThat(savedShare.getPermission()).isEqualTo(SharePermission.READ);
        assertThat(savedShare.getGrantedAt()).isNotNull();

        // Verify query by document ID and grantee username
        Optional<DocumentShare> fetched = documentShareRepository.findByDocumentIdAndGranteeUsername(doc.getId(), "carol");
        assertThat(fetched).isPresent();
        assertThat(fetched.get().getPermission()).isEqualTo(SharePermission.READ);
    }

    @Test
    @DisplayName("Unique constraint enforcement: duplicate share for same document and grantee must fail")
    void documentShare_duplicateGrant_shouldThrowDataIntegrityViolationException() {
        User owner = persistUser("dave", "dave@example.com");
        User grantee = persistUser("eve", "eve@example.com");

        Document doc = documentRepository.saveAndFlush(new Document("Design Guidelines", "Brand assets", owner));

        // First share grant succeeds
        documentShareRepository.saveAndFlush(new DocumentShare(doc, grantee, SharePermission.READ));

        // Attempting to persist a second share for the same document and grantee must violate uq_document_grantee
        DocumentShare duplicateShare = new DocumentShare(doc, grantee, SharePermission.EDIT);
        assertThatThrownBy(() -> documentShareRepository.saveAndFlush(duplicateShare))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("Grant update: updating existing share from READ to EDIT must succeed without duplicate rows")
    void documentShare_updateExistingGrant_shouldUpdatePermissionSuccessfully() {
        User owner = persistUser("frank", "frank@example.com");
        User grantee = persistUser("grace", "grace@example.com");

        Document doc = documentRepository.saveAndFlush(new Document("Sprint Backlog", "Sprint planning", owner));

        DocumentShare share = documentShareRepository.saveAndFlush(new DocumentShare(doc, grantee, SharePermission.READ));
        assertThat(share.getPermission()).isEqualTo(SharePermission.READ);

        // Update existing grant to EDIT
        share.setPermission(SharePermission.EDIT);
        DocumentShare updatedShare = documentShareRepository.saveAndFlush(share);

        assertThat(updatedShare.getPermission()).isEqualTo(SharePermission.EDIT);

        // Verify total shares for document remains exactly 1
        List<DocumentShare> shares = documentShareRepository.findByDocumentId(doc.getId());
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getPermission()).isEqualTo(SharePermission.EDIT);
    }

    @Test
    @DisplayName("JPA Set invariance: Document hashCode and equals must remain stable across persist transitions")
    void document_equalsAndHashCode_shouldPreserveSetInvarianceAcrossPersist() {
        User owner = persistUser("heidi", "heidi@example.com");

        Document transientDoc = new Document("Invariant Test Doc", "Testing Set stability", owner);
        UUID originalStorageKey = transientDoc.getStorageKey();
        assertThat(originalStorageKey).isNotNull();

        Set<Document> documentSet = new HashSet<>();
        documentSet.add(transientDoc);

        // Before persist: set contains transient document
        assertThat(documentSet).contains(transientDoc);

        Document persistedDoc = documentRepository.saveAndFlush(transientDoc);
        assertThat(persistedDoc.getId()).isNotNull();

        // After persist: set must STILL contain the document!
        // Proves that hashCode based on immutable storageKey did not mutate when id was assigned.
        assertThat(documentSet).contains(persistedDoc);
        assertThat(documentSet).contains(transientDoc);
        assertThat(transientDoc).isEqualTo(persistedDoc);
    }

    @Test
    @DisplayName("JPA Set invariance: DocumentShare hashCode and equals must remain stable across persist transitions")
    void documentShare_equalsAndHashCode_shouldPreserveSetInvarianceAcrossPersist() {
        User owner = persistUser("ivan", "ivan@example.com");
        User grantee = persistUser("judy", "judy@example.com");

        Document doc = documentRepository.saveAndFlush(new Document("Shared Invariance Doc", "Testing Share Set", owner));

        DocumentShare transientShare = new DocumentShare(doc, grantee, SharePermission.READ);

        Set<DocumentShare> shareSet = new HashSet<>();
        shareSet.add(transientShare);

        // Before persist: set contains transient share
        assertThat(shareSet).contains(transientShare);

        DocumentShare persistedShare = documentShareRepository.saveAndFlush(transientShare);
        assertThat(persistedShare.getId()).isNotNull();

        // After persist: set must STILL contain the share!
        assertThat(shareSet).contains(persistedShare);
        assertThat(shareSet).contains(transientShare);
        assertThat(transientShare).isEqualTo(persistedShare);
    }

    @Test
    @DisplayName("Cascade deletion: deleting a document must cascade and remove all associated shares")
    void document_deletion_shouldCascadeDeleteShares() {
        User owner = persistUser("ken", "ken@example.com");
        User grantee1 = persistUser("laura", "laura@example.com");
        User grantee2 = persistUser("mike", "mike@example.com");

        Document doc = documentRepository.saveAndFlush(new Document("Temporary Contract", "Legal draft", owner));
        Long docId = doc.getId();

        documentShareRepository.saveAndFlush(new DocumentShare(doc, grantee1, SharePermission.READ));
        documentShareRepository.saveAndFlush(new DocumentShare(doc, grantee2, SharePermission.EDIT));

        assertThat(documentShareRepository.findByDocumentId(docId)).hasSize(2);

        // Delete parent document
        documentRepository.delete(doc);
        documentRepository.flush();

        // Document is deleted
        assertThat(documentRepository.findById(docId)).isEmpty();

        // Associated shares must be deleted by cascade
        assertThat(documentShareRepository.findByDocumentId(docId)).isEmpty();
    }

    @Test
    @DisplayName("Accessible documents query: should return both owned and shared documents while excluding unshared")
    void findAllAccessibleByUsername_shouldReturnOwnedAndSharedDocumentsOnly() {
        User userA = persistUser("user_a", "usera@example.com");
        User userB = persistUser("user_b", "userb@example.com");
        User userC = persistUser("user_c", "userc@example.com");

        // Document 1 owned by User A
        Document doc1 = documentRepository.saveAndFlush(new Document("Doc 1 Owned by A", "A's private doc", userA));

        // Document 2 owned by User B, shared with User A
        Document doc2 = documentRepository.saveAndFlush(new Document("Doc 2 Owned by B", "B's shared doc", userB));
        documentShareRepository.saveAndFlush(new DocumentShare(doc2, userA, SharePermission.READ));

        // Document 3 owned by User C, NOT shared with User A
        Document doc3 = documentRepository.saveAndFlush(new Document("Doc 3 Owned by C", "C's unshared doc", userC));

        // Query accessible documents for User A
        List<Document> accessibleDocs = documentRepository.findAllAccessibleByUsername("user_a");

        assertThat(accessibleDocs).extracting(Document::getId)
                .contains(doc1.getId(), doc2.getId())
                .doesNotContain(doc3.getId());
    }

    @Test
    @DisplayName("SharePermission helper methods: verify READ vs EDIT permission hierarchy")
    void sharePermission_hierarchyMethods_shouldReflectAccessRules() {
        // READ permits reading, rejects editing
        assertThat(SharePermission.READ.allowsRead()).isTrue();
        assertThat(SharePermission.READ.allowsEdit()).isFalse();

        // EDIT permits reading AND editing
        assertThat(SharePermission.EDIT.allowsRead()).isTrue();
        assertThat(SharePermission.EDIT.allowsEdit()).isTrue();
    }

    @Test
    @DisplayName("File metadata: should persist and retrieve all file metadata fields correctly")
    void document_fileMetadata_shouldPersistAndRetrieveAllFields() {
        User owner = persistUser("file_user_1", "fileuser1@example.com");
        Document doc = new Document("Quarterly Financials", "Q3 Report", owner);

        Instant uploadTime = Instant.now();
        String validChecksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        UUID fileStorageKey = UUID.randomUUID();
        doc.setFileStorageKey(fileStorageKey);
        doc.setFileOriginalName("financial_report_q3.pdf");
        doc.setFileContentType("application/pdf");
        doc.setFileSize(2048576L);
        doc.setFileChecksum(validChecksum);
        doc.setFileUploadedAt(uploadTime);

        assertThat(doc.hasFile()).isTrue();
        assertThat(doc.isFileMetadataConsistent()).isTrue();

        Document savedDoc = documentRepository.saveAndFlush(doc);

        Optional<Document> fetched = documentRepository.findById(savedDoc.getId());
        assertThat(fetched).isPresent();
        Document retrieved = fetched.get();

        assertThat(retrieved.getFileStorageKey()).isEqualTo(fileStorageKey);
        assertThat(retrieved.getFileOriginalName()).isEqualTo("financial_report_q3.pdf");
        assertThat(retrieved.getFileContentType()).isEqualTo("application/pdf");
        assertThat(retrieved.getFileSize()).isEqualTo(2048576L);
        assertThat(retrieved.getFileChecksum()).isEqualTo(validChecksum);
        assertThat(retrieved.getFileUploadedAt()).isNotNull();
        assertThat(retrieved.hasFile()).isTrue();
        assertThat(retrieved.isFileMetadataConsistent()).isTrue();
    }

    @Test
    @DisplayName("File metadata: metadata-only documents should have null file fields and hasFile() false")
    void document_fileMetadata_shouldAllowNullsForMetadataOnlyDocuments() {
        User owner = persistUser("file_user_2", "fileuser2@example.com");
        Document doc = new Document("Empty Note", "No attachment", owner);

        Document saved = documentRepository.saveAndFlush(doc);

        Optional<Document> fetched = documentRepository.findById(saved.getId());
        assertThat(fetched).isPresent();
        Document retrieved = fetched.get();

        assertThat(retrieved.getFileStorageKey()).isNull();
        assertThat(retrieved.getFileOriginalName()).isNull();
        assertThat(retrieved.getFileContentType()).isNull();
        assertThat(retrieved.getFileSize()).isNull();
        assertThat(retrieved.getFileChecksum()).isNull();
        assertThat(retrieved.getFileUploadedAt()).isNull();
        assertThat(retrieved.hasFile()).isFalse();
        assertThat(retrieved.isFileMetadataConsistent()).isTrue();
    }

    @Test
    @DisplayName("File metadata: zero-byte file payload must be treated as present by hasFile()")
    void document_fileMetadata_zeroByteFile_shouldBeTreatedAsPresent() {
        User owner = persistUser("file_user_3", "fileuser3@example.com");
        Document doc = new Document("Empty File Document", "Contains zero-byte payload", owner);

        String zeroByteSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        UUID fileKey = UUID.randomUUID();
        doc.setFileMetadata(fileKey, "empty.txt", "text/plain", 0L, zeroByteSha256, Instant.now());

        // A zero-byte file is valid and hasFile() must return true
        assertThat(doc.hasFile()).isTrue();
        assertThat(doc.getFileSize()).isEqualTo(0L);

        Document saved = documentRepository.saveAndFlush(doc);
        Optional<Document> fetched = documentRepository.findById(saved.getId());
        assertThat(fetched).isPresent();
        assertThat(fetched.get().hasFile()).isTrue();
        assertThat(fetched.get().getFileSize()).isEqualTo(0L);
        assertThat(fetched.get().getFileStorageKey()).isEqualTo(fileKey);
        assertThat(fetched.get().getFileOriginalName()).isEqualTo("empty.txt");
    }

    @Test
    @DisplayName("File metadata: attaching and updating metadata must preserve storageKey and owner")
    void document_fileMetadata_attachingAndUpdating_preservesStorageKeyAndOwner() {
        User owner = persistUser("file_user_4", "fileuser4@example.com");
        Document doc = documentRepository.saveAndFlush(new Document("Draft Contract", "Legal draft", owner));

        UUID originalStorageKey = doc.getStorageKey();
        Long originalDocId = doc.getId();
        Long originalOwnerId = doc.getOwner().getId();

        assertThat(doc.hasFile()).isFalse();

        // 1. Attach file metadata
        UUID fileKey1 = UUID.randomUUID();
        doc.setFileMetadata(
                fileKey1,
                "contract_v1.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                102400L,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                Instant.now()
        );
        Document savedV1 = documentRepository.saveAndFlush(doc);

        assertThat(savedV1.getId()).isEqualTo(originalDocId);
        assertThat(savedV1.getStorageKey()).isEqualTo(originalStorageKey);
        assertThat(savedV1.getOwner().getId()).isEqualTo(originalOwnerId);
        assertThat(savedV1.hasFile()).isTrue();
        assertThat(savedV1.getFileStorageKey()).isEqualTo(fileKey1);
        assertThat(savedV1.getFileOriginalName()).isEqualTo("contract_v1.docx");

        // 2. Update/replace file metadata
        UUID fileKey2 = UUID.randomUUID();
        savedV1.setFileMetadata(
                fileKey2,
                "contract_v2.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                204800L,
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                Instant.now()
        );
        Document savedV2 = documentRepository.saveAndFlush(savedV1);

        assertThat(savedV2.getId()).isEqualTo(originalDocId);
        assertThat(savedV2.getStorageKey()).isEqualTo(originalStorageKey);
        assertThat(savedV2.getOwner().getId()).isEqualTo(originalOwnerId);
        assertThat(savedV2.hasFile()).isTrue();
        assertThat(savedV2.getFileStorageKey()).isEqualTo(fileKey2);
        assertThat(savedV2.getFileStorageKey()).isNotEqualTo(fileKey1);
        assertThat(savedV2.getFileOriginalName()).isEqualTo("contract_v2.docx");
        assertThat(savedV2.getFileSize()).isEqualTo(204800L);
        assertThat(savedV2.getFileChecksum()).isEqualTo("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    }

    @Test
    @DisplayName("Validation: negative file size must fail validation")
    void document_fileMetadata_rejectsNegativeFileSize() {
        User owner = persistUser("file_user_5", "fileuser5@example.com");
        Document doc = new Document("Negative Size Doc", "Invalid", owner);

        doc.setFileOriginalName("file.pdf");
        doc.setFileContentType("application/pdf");
        doc.setFileSize(-1L); // Violates @PositiveOrZero
        doc.setFileChecksum("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        assertThatThrownBy(() -> documentRepository.saveAndFlush(doc))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);
    }

    @Test
    @DisplayName("Validation: invalid checksum format must fail validation")
    void document_fileMetadata_rejectsInvalidChecksumFormat() {
        User owner = persistUser("file_user_6", "fileuser6@example.com");
        Document doc = new Document("Invalid Checksum Doc", "Invalid", owner);

        doc.setFileOriginalName("file.pdf");
        doc.setFileContentType("application/pdf");
        doc.setFileSize(100L);
        doc.setFileChecksum("not-a-valid-sha256-hex-digest"); // Violates 64-hex regex

        assertThatThrownBy(() -> documentRepository.saveAndFlush(doc))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);
    }

    @Test
    @DisplayName("File metadata consistency: isFileMetadataConsistent() reflects partial vs full metadata")
    void document_fileMetadata_consistencyCheck() {
        User owner = persistUser("file_user_7", "fileuser7@example.com");
        Document doc = new Document("Consistency Test", "Testing partial metadata", owner);

        // All null -> consistent
        assertThat(doc.isFileMetadataConsistent()).isTrue();

        // Partially populated -> inconsistent
        doc.setFileOriginalName("partial.txt");
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // Fully populated -> consistent
        doc.setFileMetadata(UUID.randomUUID(), "full.txt", "text/plain", 10L, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Instant.now());
        assertThat(doc.isFileMetadataConsistent()).isTrue();

        // Cleared -> consistent
        doc.clearFileMetadata();
        assertThat(doc.isFileMetadataConsistent()).isTrue();
        assertThat(doc.hasFile()).isFalse();
    }

    @Test
    @DisplayName("File metadata: incomplete metadata (missing any of the 6 fields) must return hasFile() false and isFileMetadataConsistent() false")
    void document_fileMetadata_incompleteMetadata_shouldReturnHasFileFalse() {
        User owner = persistUser("file_user_8", "fileuser8@example.com");
        Document doc = new Document("Incomplete Doc", "Testing incomplete states", owner);

        String checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Instant now = Instant.now();
        UUID fileKey = UUID.randomUUID();

        // 5 of 6 fields: missing fileStorageKey
        doc.setFileStorageKey(null);
        doc.setFileOriginalName("file.pdf");
        doc.setFileContentType("application/pdf");
        doc.setFileSize(100L);
        doc.setFileChecksum(checksum);
        doc.setFileUploadedAt(now);
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // 5 of 6 fields: missing fileUploadedAt
        doc.setFileStorageKey(fileKey);
        doc.setFileUploadedAt(null);
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // 5 of 6 fields: missing fileContentType
        doc.setFileUploadedAt(now);
        doc.setFileContentType(null);
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // 5 of 6 fields: missing fileOriginalName
        doc.setFileContentType("application/pdf");
        doc.setFileOriginalName(null);
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // 5 of 6 fields: missing fileChecksum
        doc.setFileOriginalName("file.pdf");
        doc.setFileChecksum(null);
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // 5 of 6 fields: missing fileSize
        doc.setFileChecksum(checksum);
        doc.setFileSize(null);
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // All 6 fields present -> hasFile() is true and consistent
        doc.setFileSize(100L);
        assertThat(doc.hasFile()).isTrue();
        assertThat(doc.isFileMetadataConsistent()).isTrue();
    }

    @Test
    @DisplayName("setFileMetadata: rejects invalid arguments immediately and preserves entity state without mutation")
    void setFileMetadata_rejectsInvalidArgumentsAndPreservesEntityState() {
        User owner = persistUser("file_user_9", "fileuser9@example.com");
        Document doc = new Document("Validation Doc", "Testing setFileMetadata validation", owner);

        String validChecksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Instant now = Instant.now();
        UUID validFileKey = UUID.randomUUID();

        // 0. Null file storage key
        assertThatThrownBy(() -> doc.setFileMetadata(null, "report.txt", "text/plain", 100L, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("File storage key must not be null");
        assertThat(doc.hasFile()).isFalse();

        // 1. Null or blank filename
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, null, "text/plain", 100L, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Original filename must not be null or blank");
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "   ", "text/plain", 100L, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Original filename must not be null or blank");
        assertThat(doc.hasFile()).isFalse();

        // 2. Null or blank content type
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "report.txt", null, 100L, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Content type must not be null or blank");
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "report.txt", "  ", 100L, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Content type must not be null or blank");
        assertThat(doc.hasFile()).isFalse();

        // 3. Null or negative size
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "report.txt", "text/plain", null, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("File size must not be null and must be non-negative");
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "report.txt", "text/plain", -1L, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("File size must not be null and must be non-negative");
        assertThat(doc.hasFile()).isFalse();

        // 4. Null or invalid checksum
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "report.txt", "text/plain", 100L, null, now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("File checksum must not be null");
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "report.txt", "text/plain", 100L, "short-checksum", now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("File checksum must be a 64-character hexadecimal SHA-256 hash");
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "report.txt", "text/plain", 100L, validChecksum + "extra", now))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("File checksum must be a 64-character hexadecimal SHA-256 hash");
        assertThat(doc.hasFile()).isFalse();

        // 5. Successful setFileMetadata with trimming and checksum normalization
        String upperChecksum = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        doc.setFileMetadata(validFileKey, "  document.pdf  ", "  application/pdf  ", 500L, upperChecksum, now);

        assertThat(doc.hasFile()).isTrue();
        assertThat(doc.getFileStorageKey()).isEqualTo(validFileKey);
        assertThat(doc.getFileOriginalName()).isEqualTo("document.pdf");
        assertThat(doc.getFileContentType()).isEqualTo("application/pdf");
        assertThat(doc.getFileSize()).isEqualTo(500L);
        assertThat(doc.getFileChecksum()).isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); // Lowercased!

        // 6. Failed update does NOT mutate previously valid state
        assertThatThrownBy(() -> doc.setFileMetadata(validFileKey, "new.pdf", "application/pdf", -5L, validChecksum, now))
                .isInstanceOf(IllegalArgumentException.class);

        // Verify entity retained its previous valid metadata
        assertThat(doc.hasFile()).isTrue();
        assertThat(doc.getFileStorageKey()).isEqualTo(validFileKey);
        assertThat(doc.getFileOriginalName()).isEqualTo("document.pdf");
        assertThat(doc.getFileSize()).isEqualTo(500L);
    }

    @Test
    @DisplayName("File storage key: persistence and reload via findById and findByFileStorageKey")
    void document_fileStorageKey_persistedAndReloadedByRepository() {
        User owner = persistUser("file_user_10", "fileuser10@example.com");
        Document doc = new Document("Blob Key Test Doc", "Testing fileStorageKey persistence", owner);

        UUID fileKey = UUID.randomUUID();
        String validChecksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Instant now = Instant.now();

        doc.setFileMetadata(fileKey, "document.pdf", "application/pdf", 1024L, validChecksum, now);
        Document saved = documentRepository.saveAndFlush(doc);

        // 1. Reload by primary key
        Document reloadedById = documentRepository.findById(saved.getId()).orElseThrow();
        assertThat(reloadedById.getFileStorageKey()).isEqualTo(fileKey);
        assertThat(reloadedById.hasFile()).isTrue();

        // 2. Reload by fileStorageKey query method
        Document reloadedByFileKey = documentRepository.findByFileStorageKey(fileKey).orElseThrow();
        assertThat(reloadedByFileKey.getId()).isEqualTo(saved.getId());
        assertThat(reloadedByFileKey.getStorageKey()).isEqualTo(saved.getStorageKey());
        assertThat(reloadedByFileKey.getFileOriginalName()).isEqualTo("document.pdf");
    }

    @Test
    @DisplayName("File storage key: clearing file metadata clears fileStorageKey and reverts to metadata-only")
    void document_fileStorageKey_clearingFileMetadataClearsStorageKey() {
        User owner = persistUser("file_user_11", "fileuser11@example.com");
        Document doc = new Document("Clear Storage Key Doc", "Testing clearFileMetadata with storage key", owner);

        UUID fileKey = UUID.randomUUID();
        String validChecksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        doc.setFileMetadata(fileKey, "data.csv", "text/csv", 2048L, validChecksum, Instant.now());

        Document savedWithFile = documentRepository.saveAndFlush(doc);
        assertThat(savedWithFile.getFileStorageKey()).isEqualTo(fileKey);
        assertThat(savedWithFile.hasFile()).isTrue();

        savedWithFile.clearFileMetadata();
        assertThat(savedWithFile.getFileStorageKey()).isNull();
        assertThat(savedWithFile.hasFile()).isFalse();
        assertThat(savedWithFile.isFileMetadataConsistent()).isTrue();

        Document clearedInDb = documentRepository.saveAndFlush(savedWithFile);
        Document reloaded = documentRepository.findById(clearedInDb.getId()).orElseThrow();
        assertThat(reloaded.getFileStorageKey()).isNull();
        assertThat(reloaded.getFileOriginalName()).isNull();
        assertThat(reloaded.hasFile()).isFalse();
        assertThat(reloaded.isFileMetadataConsistent()).isTrue();
    }

    @Test
    @DisplayName("File storage key: replacing file updates fileStorageKey while strictly preserving logical storageKey")
    void document_fileStorageKey_replacingFileChangesFileStorageKeyWhilePreservingLogicalStorageKey() {
        User owner = persistUser("file_user_12", "fileuser12@example.com");
        Document doc = new Document("Replacement Key Doc", "Testing key decoupling", owner);

        UUID originalLogicalStorageKey = doc.getStorageKey();
        UUID fileKey1 = UUID.randomUUID();
        UUID fileKey2 = UUID.randomUUID();
        String checksum1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String checksum2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Initial upload: File V1
        doc.setFileMetadata(fileKey1, "version1.pdf", "application/pdf", 1000L, checksum1, Instant.now());
        Document savedV1 = documentRepository.saveAndFlush(doc);

        assertThat(savedV1.getStorageKey()).isEqualTo(originalLogicalStorageKey);
        assertThat(savedV1.getFileStorageKey()).isEqualTo(fileKey1);

        // Replacement upload: File V2
        savedV1.setFileMetadata(fileKey2, "version2.pdf", "application/pdf", 2000L, checksum2, Instant.now());
        Document savedV2 = documentRepository.saveAndFlush(savedV1);

        // Logical storageKey MUST remain completely invariant
        assertThat(savedV2.getStorageKey()).isEqualTo(originalLogicalStorageKey);
        // Physical fileStorageKey MUST point to the new blob
        assertThat(savedV2.getFileStorageKey()).isEqualTo(fileKey2);
        assertThat(savedV2.getFileStorageKey()).isNotEqualTo(fileKey1);
    }

    @Test
    @DisplayName("File storage key: partial state with or without fileStorageKey is flagged as inconsistent")
    void document_fileStorageKey_missingStorageKeyLeavesMetadataInconsistent() {
        User owner = persistUser("file_user_13", "fileuser13@example.com");
        Document doc = new Document("Inconsistency Doc", "Testing partial states", owner);

        String validChecksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Instant now = Instant.now();

        // 1. Only fileStorageKey set -> inconsistent
        doc.setFileStorageKey(UUID.randomUUID());
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // 2. All file fields set EXCEPT fileStorageKey -> inconsistent
        doc.setFileStorageKey(null);
        doc.setFileOriginalName("report.pdf");
        doc.setFileContentType("application/pdf");
        doc.setFileSize(500L);
        doc.setFileChecksum(validChecksum);
        doc.setFileUploadedAt(now);
        assertThat(doc.hasFile()).isFalse();
        assertThat(doc.isFileMetadataConsistent()).isFalse();

        // 3. Complete with fileStorageKey -> consistent
        doc.setFileStorageKey(UUID.randomUUID());
        assertThat(doc.hasFile()).isTrue();
        assertThat(doc.isFileMetadataConsistent()).isTrue();
    }
}
