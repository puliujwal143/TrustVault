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
}
