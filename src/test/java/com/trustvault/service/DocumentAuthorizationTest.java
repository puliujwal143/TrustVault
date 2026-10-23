package com.trustvault.service;

import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.Role;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.exception.ResourceNotFoundException;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Service-layer authorization tests for document ownership, sharing, and access control.
 *
 * Verifies all 15 security and authorization requirements:
 * 1. Owner can read and edit their own document.
 * 2. Owner can delete their own document.
 * 3. Owner can grant and revoke access.
 * 4. READ grantee can read but cannot edit.
 * 5. EDIT grantee can read and edit but cannot delete or share.
 * 6. An unshared user cannot read, edit, delete, or discover another user's document.
 * 7. ROLE_ADMIN user without a grant cannot read another user's private document.
 * 8. A user cannot grant access to their own document to themselves.
 * 9. Granting access to a nonexistent user is rejected safely.
 * 10. Granting access to a disabled user is rejected.
 * 11. Changing an existing grant updates the same row without creating a duplicate.
 * 12. Revocation immediately blocks subsequent reads and edits.
 * 13. Listing documents includes only documents owned by or shared with the caller.
 * 14. Missing documents are handled without exposing existence-sensitive details.
 * 15. Disabled user cannot access document even with an existing grant.
 * 16. Negative test cases for boundary validation, disabled-owner policy, and concurrent operations.
 */
@SpringBootTest
class DocumentAuthorizationTest {

    @Autowired
    private DocumentService documentService;

    @Autowired
    private DocumentShareService documentShareService;

    @Autowired
    private DocumentAuthorizationService authorizationService;

    @Autowired
    private UserService userService;

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

    private User createTestUser(String username, String email, Role role, boolean enabled) {
        User user = new User(username, "$2a$12$N9qo8uLOickgx2ZMRZoMye.I1z4mKjM97B8Z9e5K.sZz1mNqG9cK2", email, role);
        user.setEnabled(enabled);
        return userRepository.saveAndFlush(user);
    }

    @Test
    @DisplayName("1. Owner can read and edit their own document")
    void owner_canReadAndEditOwnDocument() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Original Title", "Original Description", "alice");
        Long docId = doc.getId();

        // Owner can read
        Document fetched = documentService.getDocument(docId, "alice");
        assertThat(fetched.getTitle()).isEqualTo("Original Title");
        assertThat(authorizationService.canRead(docId, "alice")).isTrue();

        // Owner can edit
        Document updated = documentService.updateDocument(docId, "Updated Title", "Updated Description", "alice");
        assertThat(updated.getTitle()).isEqualTo("Updated Title");
        assertThat(updated.getDescription()).isEqualTo("Updated Description");
        assertThat(authorizationService.canEdit(docId, "alice")).isTrue();
    }

    @Test
    @DisplayName("2. Owner can delete their own document")
    void owner_canDeleteOwnDocument() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("To Delete", "Delete Me", "alice");
        Long docId = doc.getId();

        documentService.deleteDocument(docId, "alice");

        // Subsequent get throws ResourceNotFoundException (404)
        assertThatThrownBy(() -> documentService.getDocument(docId, "alice"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found");
    }

    @Test
    @DisplayName("3. Owner can grant and revoke access")
    void owner_canGrantAndRevokeAccess() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Shared Doc", "Desc", "alice");
        Long docId = doc.getId();

        // Grant access
        DocumentShare share = documentShareService.grantAccess(docId, "bob", SharePermission.READ, "alice");
        assertThat(share.getPermission()).isEqualTo(SharePermission.READ);

        List<DocumentShare> shares = documentShareService.listShares(docId, "alice");
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getGrantee().getUsername()).isEqualTo("bob");

        // Revoke access
        documentShareService.revokeAccess(docId, "bob", "alice");
        assertThat(documentShareService.listShares(docId, "alice")).isEmpty();
    }

    @Test
    @DisplayName("4. READ grantee can read but cannot edit or modify")
    void readGrantee_canRead_cannotEdit() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Read Only Doc", "Desc", "alice");
        Long docId = doc.getId();
        documentShareService.grantAccess(docId, "bob", SharePermission.READ, "alice");

        // Bob can read
        Document fetched = documentService.getDocument(docId, "bob");
        assertThat(fetched.getTitle()).isEqualTo("Read Only Doc");
        assertThat(authorizationService.canRead(docId, "bob")).isTrue();

        // Bob cannot edit -> throws AccessDeniedException (403)
        assertThat(authorizationService.canEdit(docId, "bob")).isFalse();
        assertThatThrownBy(() -> documentService.updateDocument(docId, "Hacked Title", "Hacked Desc", "bob"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Insufficient permission to modify document");
    }

    @Test
    @DisplayName("5. EDIT grantee can read and edit, but cannot delete or manage shares")
    void editGrantee_canReadAndEdit_cannotDeleteOrShare() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("carol", "carol@example.com", Role.ROLE_USER, true);
        createTestUser("dave", "dave@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Collaborative Doc", "Initial", "alice");
        Long docId = doc.getId();
        documentShareService.grantAccess(docId, "carol", SharePermission.EDIT, "alice");

        // Carol can read
        assertThat(authorizationService.canRead(docId, "carol")).isTrue();
        assertThat(documentService.getDocument(docId, "carol").getTitle()).isEqualTo("Collaborative Doc");

        // Carol can edit
        assertThat(authorizationService.canEdit(docId, "carol")).isTrue();
        Document updated = documentService.updateDocument(docId, "Carol Updated Title", "New Content", "carol");
        assertThat(updated.getTitle()).isEqualTo("Carol Updated Title");

        // Carol CANNOT delete -> 403 Forbidden
        assertThatThrownBy(() -> documentService.deleteDocument(docId, "carol"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only the document owner can perform this operation");

        // Carol CANNOT grant access to Dave -> 403 Forbidden
        assertThatThrownBy(() -> documentShareService.grantAccess(docId, "dave", SharePermission.READ, "carol"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only the document owner can perform this operation");

        // Carol CANNOT list shares -> 403 Forbidden
        assertThatThrownBy(() -> documentShareService.listShares(docId, "carol"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only the document owner can perform this operation");

        // Carol CANNOT revoke shares -> 403 Forbidden
        assertThatThrownBy(() -> documentShareService.revokeAccess(docId, "dave", "carol"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only the document owner can perform this operation");
    }

    @Test
    @DisplayName("6. Unshared user cannot read, edit, delete, or discover another user's document (404 anti-IDOR)")
    void unsharedUser_cannotReadEditDeleteOrDiscoverDocument() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("mallory", "mallory@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Alice Private Vault", "Top Secret", "alice");
        Long docId = doc.getId();

        assertThat(authorizationService.canRead(docId, "mallory")).isFalse();
        assertThat(authorizationService.canEdit(docId, "mallory")).isFalse();
        assertThat(authorizationService.isOwner(docId, "mallory")).isFalse();

        // Attempting to read returns 404 (anti-enumeration)
        assertThatThrownBy(() -> documentService.getDocument(docId, "mallory"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        // Attempting to edit returns 404 (does not leak document existence)
        assertThatThrownBy(() -> documentService.updateDocument(docId, "Hacked", "Desc", "mallory"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        // Attempting to delete returns 404
        assertThatThrownBy(() -> documentService.deleteDocument(docId, "mallory"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        // Attempting to list shares returns 404
        assertThatThrownBy(() -> documentShareService.listShares(docId, "mallory"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);
    }

    @Test
    @DisplayName("7. ROLE_ADMIN user without a grant cannot access private user documents")
    void adminUser_withoutGrant_cannotReadPrivateDocument() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("admin", "admin@trustvault.internal", Role.ROLE_ADMIN, true);

        Document doc = documentService.createDocument("Alice Personal Notes", "Private", "alice");
        Long docId = doc.getId();

        // Admin has no grant and is not owner: must be denied with 404 (no auto-bypass)
        assertThat(authorizationService.canRead(docId, "admin")).isFalse();
        assertThat(authorizationService.canEdit(docId, "admin")).isFalse();

        assertThatThrownBy(() -> documentService.getDocument(docId, "admin"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        assertThatThrownBy(() -> documentService.updateDocument(docId, "Admin Override", "Desc", "admin"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        assertThatThrownBy(() -> documentService.deleteDocument(docId, "admin"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);
    }

    @Test
    @DisplayName("8. Document owner cannot grant access to themselves")
    void owner_cannotGrantAccessToSelf() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Self Grant Doc", "Desc", "alice");
        Long docId = doc.getId();

        assertThatThrownBy(() -> documentShareService.grantAccess(docId, "alice", SharePermission.READ, "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document owners cannot grant access to themselves");
    }

    @Test
    @DisplayName("9. Granting access to nonexistent user is rejected safely")
    void grantAccess_nonexistentUser_rejectedSafely() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Doc for Ghost", "Desc", "alice");
        Long docId = doc.getId();

        assertThatThrownBy(() -> documentShareService.grantAccess(docId, "ghost_user", SharePermission.READ, "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Grantee user not found: ghost_user");
    }

    @Test
    @DisplayName("10. Granting access to disabled user is rejected")
    void grantAccess_disabledUser_rejected() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("disabled_bob", "disabled@example.com", Role.ROLE_USER, false); // disabled

        Document doc = documentService.createDocument("Doc for Inactive", "Desc", "alice");
        Long docId = doc.getId();

        assertThatThrownBy(() -> documentShareService.grantAccess(docId, "disabled_bob", SharePermission.READ, "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Cannot grant access to disabled user: disabled_bob");
    }

    @Test
    @DisplayName("11. Changing an existing grant updates the same row without creating duplicates")
    void changeExistingGrant_updatesSameRowWithoutDuplicate() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("eve", "eve@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Contract V1", "Desc", "alice");
        Long docId = doc.getId();

        // Initial READ grant
        DocumentShare firstGrant = documentShareService.grantAccess(docId, "eve", SharePermission.READ, "alice");
        assertThat(firstGrant.getPermission()).isEqualTo(SharePermission.READ);

        // Update to EDIT grant
        DocumentShare updatedGrant = documentShareService.grantAccess(docId, "eve", SharePermission.EDIT, "alice");
        assertThat(updatedGrant.getPermission()).isEqualTo(SharePermission.EDIT);
        assertThat(updatedGrant.getId()).isEqualTo(firstGrant.getId()); // Preserves identical record ID

        // Verify total shares for document is exactly 1
        List<DocumentShare> shares = documentShareService.listShares(docId, "alice");
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getPermission()).isEqualTo(SharePermission.EDIT);
    }

    @Test
    @DisplayName("12. Revoking a grant immediately stops authorizing subsequent reads and edits")
    void revocation_immediatelyBlocksSubsequentReadsAndEdits() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("frank", "frank@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Top Secret Project", "Desc", "alice");
        Long docId = doc.getId();

        documentShareService.grantAccess(docId, "frank", SharePermission.EDIT, "alice");

        // Frank can access initially
        assertThat(authorizationService.canRead(docId, "frank")).isTrue();
        assertThat(documentService.getDocument(docId, "frank")).isNotNull();

        // Alice revokes Frank's access
        documentShareService.revokeAccess(docId, "frank", "alice");

        // Immediately after revocation, Frank cannot read or edit -> 404 (grant no longer exists)
        assertThat(authorizationService.canRead(docId, "frank")).isFalse();
        assertThat(authorizationService.canEdit(docId, "frank")).isFalse();

        assertThatThrownBy(() -> documentService.getDocument(docId, "frank"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        assertThatThrownBy(() -> documentService.updateDocument(docId, "Malicious", "Desc", "frank"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);
    }

    @Test
    @DisplayName("13. Listing accessible documents includes owned and shared, excluding unshared")
    void listAccessibleDocuments_includesOnlyOwnedAndSharedDocuments() {
        createTestUser("user_a", "usera@example.com", Role.ROLE_USER, true);
        createTestUser("user_b", "userb@example.com", Role.ROLE_USER, true);
        createTestUser("user_c", "userc@example.com", Role.ROLE_USER, true);

        // User A owns Doc 1
        Document doc1 = documentService.createDocument("Doc 1 by A", "Owned by A", "user_a");

        // User B owns Doc 2, shared with User A
        Document doc2 = documentService.createDocument("Doc 2 by B", "Shared with A", "user_b");
        documentShareService.grantAccess(doc2.getId(), "user_a", SharePermission.READ, "user_b");

        // User C owns Doc 3, unshared
        Document doc3 = documentService.createDocument("Doc 3 by C", "Private to C", "user_c");

        // Query accessible docs for User A
        List<Document> accessible = documentService.listAccessibleDocuments("user_a");
        assertThat(accessible).extracting(Document::getId)
                .contains(doc1.getId(), doc2.getId())
                .doesNotContain(doc3.getId());
    }

    @Test
    @DisplayName("14. Missing documents return 404 without exposing existence-sensitive details")
    void missingDocument_handledWithoutExposingExistenceDetails() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Long nonexistentDocId = 999999L;

        assertThatThrownBy(() -> documentService.getDocument(nonexistentDocId, "alice"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + nonexistentDocId);

        assertThatThrownBy(() -> documentService.updateDocument(nonexistentDocId, "Title", "Desc", "alice"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + nonexistentDocId);

        assertThatThrownBy(() -> documentService.deleteDocument(nonexistentDocId, "alice"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + nonexistentDocId);
    }

    @Test
    @DisplayName("15. Disabled user cannot access document even if a grant previously existed")
    void disabledUser_cannotAccessEvenWithExistingGrant() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        User grace = createTestUser("grace", "grace@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Grace Collaboration", "Desc", "alice");
        Long docId = doc.getId();
        documentShareService.grantAccess(docId, "grace", SharePermission.READ, "alice");

        // Grace can read while active
        assertThat(authorizationService.canRead(docId, "grace")).isTrue();

        // Deactivate Grace's account
        grace.setEnabled(false);
        userRepository.saveAndFlush(grace);

        // Disabled user is immediately blocked from discovery/reading
        assertThat(authorizationService.canRead(docId, "grace")).isFalse();
        assertThatThrownBy(() -> documentService.getDocument(docId, "grace"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);
    }

    @Test
    @DisplayName("16. Revoking a nonexistent share throws ResourceNotFoundException")
    void revokeAccess_nonexistentShare_throwsResourceNotFoundException() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Alice Doc", "Desc", "alice");
        Long docId = doc.getId();

        assertThatThrownBy(() -> documentShareService.revokeAccess(docId, "bob", "alice"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("No active share grant found for user: bob");
    }

    @Test
    @DisplayName("17. Creating a document for a disabled owner throws IllegalStateException")
    void createDocument_disabledOwner_throwsIllegalStateException() {
        createTestUser("disabled_owner", "disabled@example.com", Role.ROLE_USER, false);

        assertThatThrownBy(() -> documentService.createDocument("Title", "Desc", "disabled_owner"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Disabled account cannot create documents: disabled_owner");
    }

    @Test
    @DisplayName("18. Blank or null document title is rejected with IllegalArgumentException")
    void createDocument_blankOrNullTitle_throwsIllegalArgumentException() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        // Null title
        assertThatThrownBy(() -> documentService.createDocument(null, "Desc", "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document title must not be blank");

        // Blank title
        assertThatThrownBy(() -> documentService.createDocument("   ", "Desc", "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document title must not be blank");
    }

    @Test
    @DisplayName("19. Document title exceeding 255 characters is rejected with IllegalArgumentException")
    void createDocument_titleExceeds255Chars_throwsIllegalArgumentException() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        String longTitle = "A".repeat(256);
        assertThatThrownBy(() -> documentService.createDocument(longTitle, "Desc", "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document title must not exceed 255 characters");
    }

    @Test
    @DisplayName("20. Document description exceeding 1000 characters is rejected with IllegalArgumentException")
    void createDocument_descriptionExceeds1000Chars_throwsIllegalArgumentException() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        String longDescription = "D".repeat(1001);
        assertThatThrownBy(() -> documentService.createDocument("Valid Title", longDescription, "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document description must not exceed 1000 characters");
    }

    @Test
    @DisplayName("21. Updating a document with invalid title or description is rejected with IllegalArgumentException")
    void updateDocument_invalidTitleOrDescription_throwsIllegalArgumentException() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        Document doc = documentService.createDocument("Original Title", "Original Desc", "alice");
        Long docId = doc.getId();

        // Blank update title
        assertThatThrownBy(() -> documentService.updateDocument(docId, "  ", "New Desc", "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document title must not be blank");

        // Excessively long title
        assertThatThrownBy(() -> documentService.updateDocument(docId, "T".repeat(256), "New Desc", "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document title must not exceed 255 characters");

        // Excessively long description
        assertThatThrownBy(() -> documentService.updateDocument(docId, "New Title", "D".repeat(1001), "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document description must not exceed 1000 characters");
    }

    @Test
    @DisplayName("22. Disabled-owner policy: documents inaccessible to grantees and omitted from listings; resume when reactivated")
    void disabledOwner_documentsInaccessibleToGrantees_andOmittedFromListing() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Alice Secret", "Important", "alice");
        Long docId = doc.getId();
        documentShareService.grantAccess(docId, "bob", SharePermission.READ, "alice");

        // Initial state: Bob can read and see in listing
        assertThat(authorizationService.canRead(docId, "bob")).isTrue();
        assertThat(documentService.getDocument(docId, "bob").getTitle()).isEqualTo("Alice Secret");
        List<Document> bobAccessible = documentService.listAccessibleDocuments("bob");
        assertThat(bobAccessible).extracting(Document::getId).contains(docId);

        // Deactivate Alice (the owner)
        userService.deactivateUser("alice");

        // Grantees cannot read or edit disabled owner's documents (return 404)
        assertThat(authorizationService.canRead(docId, "bob")).isFalse();
        assertThat(authorizationService.canEdit(docId, "bob")).isFalse();
        assertThatThrownBy(() -> documentService.getDocument(docId, "bob"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        // Disabled owner's documents are omitted from grantee's accessible list
        List<Document> bobAccessibleAfterDeactivation = documentService.listAccessibleDocuments("bob");
        assertThat(bobAccessibleAfterDeactivation).extracting(Document::getId).doesNotContain(docId);

        // Verify document and share records remain intact in database
        assertThat(documentRepository.findById(docId)).isPresent();
        assertThat(documentShareRepository.findByDocumentId(docId)).hasSize(1);

        // Reactivate Alice
        userService.reactivateUser("alice");

        // Access resumes according to existing grants
        assertThat(authorizationService.canRead(docId, "bob")).isTrue();
        assertThat(documentService.getDocument(docId, "bob").getTitle()).isEqualTo("Alice Secret");
        List<Document> bobAccessibleAfterReactivation = documentService.listAccessibleDocuments("bob");
        assertThat(bobAccessibleAfterReactivation).extracting(Document::getId).contains(docId);
    }

    @Test
    @DisplayName("23. Concurrent share grants serialize cleanly without duplicate rows or integrity errors")
    void concurrentShareGrants_serializedCleanlyWithoutDuplicateOrError() throws Exception {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Concurrent Share Doc", "Desc", "alice");
        Long docId = doc.getId();

        int threads = 4;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch readyLatch = new CountDownLatch(threads);
        CountDownLatch startLatch = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            final SharePermission perm = (i % 2 == 0) ? SharePermission.READ : SharePermission.EDIT;
            futures.add(executor.submit(() -> {
                readyLatch.countDown();
                try {
                    startLatch.await();
                    documentShareService.grantAccess(docId, "bob", perm, "alice");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
        }

        readyLatch.await(5, TimeUnit.SECONDS);
        startLatch.countDown();

        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        executor.shutdown();

        // Exactly 1 share record exists for bob on this document
        List<DocumentShare> shares = documentShareService.listShares(docId, "alice");
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getGrantee().getUsername()).isEqualTo("bob");
        assertThat(shares.get(0).getPermission()).isIn(SharePermission.READ, SharePermission.EDIT);
    }

    @Test
    @DisplayName("24. Locked authorization methods (forUpdate) strictly enforce owner and EDIT permissions under lock")
    void lockedAuthorization_enforcesPermissionsCorrectlyUnderPessimisticLock() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);
        createTestUser("carol", "carol@example.com", Role.ROLE_USER, true);
        createTestUser("mallory", "mallory@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Locked Doc", "Desc", "alice");
        Long docId = doc.getId();

        documentShareService.grantAccess(docId, "bob", SharePermission.EDIT, "alice");
        documentShareService.grantAccess(docId, "carol", SharePermission.READ, "alice");

        // getAuthorizedDocumentForUpdate: owner and EDIT grantee succeed
        assertThat(authorizationService.getAuthorizedDocumentForUpdate(docId, "alice", SharePermission.EDIT)).isNotNull();
        assertThat(authorizationService.getAuthorizedDocumentForUpdate(docId, "bob", SharePermission.EDIT)).isNotNull();

        // getAuthorizedDocumentForUpdate: READ grantee attempting EDIT receives 403 Forbidden
        assertThatThrownBy(() -> authorizationService.getAuthorizedDocumentForUpdate(docId, "carol", SharePermission.EDIT))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Insufficient permission to modify document");

        // getAuthorizedDocumentForUpdate: unshared user receives 404 Not Found
        assertThatThrownBy(() -> authorizationService.getAuthorizedDocumentForUpdate(docId, "mallory", SharePermission.EDIT))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);

        // getAuthorizedDocumentForOwnerForUpdate: owner succeeds
        assertThat(authorizationService.getAuthorizedDocumentForOwnerForUpdate(docId, "alice")).isNotNull();

        // getAuthorizedDocumentForOwnerForUpdate: grantee receives 403 Forbidden
        assertThatThrownBy(() -> authorizationService.getAuthorizedDocumentForOwnerForUpdate(docId, "bob"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only the document owner can perform this operation");

        // getAuthorizedDocumentForOwnerForUpdate: unshared user receives 404 Not Found
        assertThatThrownBy(() -> authorizationService.getAuthorizedDocumentForOwnerForUpdate(docId, "mallory"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found: " + docId);
    }

    @Test
    @DisplayName("25. Concurrent update and revocation coordinate cleanly under pessimistic lock")
    void concurrentUpdateAndRevocation_serializedCleanlyUnderPessimisticLock() throws Exception {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Initial Title", "Desc", "alice");
        Long docId = doc.getId();
        documentShareService.grantAccess(docId, "bob", SharePermission.EDIT, "alice");

        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch readyLatch = new CountDownLatch(2);
        CountDownLatch startLatch = new CountDownLatch(1);

        Future<Boolean> updateFuture = executor.submit(() -> {
            readyLatch.countDown();
            try {
                startLatch.await();
                documentService.updateDocument(docId, "Concurrent Updated Title", "New Content", "bob");
                return true;
            } catch (ResourceNotFoundException e) {
                // Revocation committed first; update rejected with 404
                return false;
            }
        });

        Future<Boolean> revokeFuture = executor.submit(() -> {
            readyLatch.countDown();
            try {
                startLatch.await();
                documentShareService.revokeAccess(docId, "bob", "alice");
                return true;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        readyLatch.await(5, TimeUnit.SECONDS);
        startLatch.countDown();

        boolean updateSucceeded = updateFuture.get(10, TimeUnit.SECONDS);
        boolean revokeSucceeded = revokeFuture.get(10, TimeUnit.SECONDS);
        executor.shutdown();

        // Revocation always succeeds
        assertThat(revokeSucceeded).isTrue();

        // Verify state is consistent: Bob has no active share
        assertThat(documentShareService.listShares(docId, "alice")).isEmpty();

        // Either update succeeded before revocation or was safely rejected with 404
        Document finalDoc = documentRepository.findById(docId).orElseThrow();
        if (updateSucceeded) {
            assertThat(finalDoc.getTitle()).isEqualTo("Concurrent Updated Title");
        } else {
            assertThat(finalDoc.getTitle()).isEqualTo("Initial Title");
        }
    }

    @Test
    @DisplayName("26. createDocument: persists and trims valid category, normalizes blank to null")
    void createDocument_withCategory_persistsAndNormalizes() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Document docWithCategory = documentService.createDocument("Finances", "Summary", "  Finance  ", "alice");
        assertThat(docWithCategory.getCategory()).isEqualTo("Finance");

        Document docWithBlankCategory = documentService.createDocument("Notes", "Desc", "   ", "alice");
        assertThat(docWithBlankCategory.getCategory()).isNull();
    }

    @Test
    @DisplayName("27. createDocument: category exceeding 50 characters throws IllegalArgumentException")
    void createDocument_categoryExceeding50Chars_throwsIllegalArgumentException() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        assertThatThrownBy(() -> documentService.createDocument("Title", "Desc", "C".repeat(51), "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document category must not exceed 50 characters");
    }

    @Test
    @DisplayName("28. updateDocument: updates category, trims input, and rejects category exceeding 50 characters")
    void updateDocument_withCategory_updatesAndValidates() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Document doc = documentService.createDocument("Contract", "Initial", "Finance", "alice");
        Long docId = doc.getId();

        // Update category
        Document updated = documentService.updateDocument(docId, "Contract", "Updated", "  Legal  ", "alice");
        assertThat(updated.getCategory()).isEqualTo("Legal");

        // Clear category to null via blank
        Document cleared = documentService.updateDocument(docId, "Contract", "Updated", "   ", "alice");
        assertThat(cleared.getCategory()).isNull();

        // Rejects > 50 characters
        assertThatThrownBy(() -> documentService.updateDocument(docId, "Contract", "Desc", "L".repeat(51), "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Document category must not exceed 50 characters");
    }

    @Test
    @DisplayName("29. searchAccessibleDocuments: category filtering matches case-insensitively and returns matching accessible docs")
    void searchAccessibleDocuments_filterByCategory() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);

        Document doc1 = documentService.createDocument("Q1 Report", "Desc", "Finance", "alice");
        Document doc2 = documentService.createDocument("Employment Agreement", "Desc", "Legal", "alice");
        Document doc3 = documentService.createDocument("Architecture Spec", "Desc", "Engineering", "alice");

        List<Document> financeDocs = documentService.searchAccessibleDocuments("alice", null, null, "fin", null, null);
        assertThat(financeDocs).extracting(Document::getId).containsExactly(doc1.getId());

        List<Document> legalDocs = documentService.searchAccessibleDocuments("alice", null, null, "LEGAL", null, null);
        assertThat(legalDocs).extracting(Document::getId).containsExactly(doc2.getId());

        List<Document> allDocs = documentService.searchAccessibleDocuments("alice", null, null, null, null, null);
        assertThat(allDocs).extracting(Document::getId).contains(doc1.getId(), doc2.getId(), doc3.getId());
    }

    @Test
    @DisplayName("30. searchAccessibleDocuments: category filtering strictly isolates unauthorized documents across users")
    void searchAccessibleDocuments_crossUserIsolation() {
        createTestUser("alice", "alice@example.com", Role.ROLE_USER, true);
        createTestUser("bob", "bob@example.com", Role.ROLE_USER, true);
        createTestUser("mallory", "mallory@example.com", Role.ROLE_USER, true);

        Document aliceSecret = documentService.createDocument("Alice Top Secret", "Classified", "TopSecret", "alice");
        Document bobSecret = documentService.createDocument("Bob Secret Recipe", "Cooking", "TopSecret", "bob");

        // Bob searches for "TopSecret" -> receives ONLY Bob's document, NEVER Alice's
        List<Document> bobResults = documentService.searchAccessibleDocuments("bob", null, null, "TopSecret", null, null);
        assertThat(bobResults).extracting(Document::getId).containsExactly(bobSecret.getId());
        assertThat(bobResults).extracting(Document::getTitle).doesNotContain("Alice Top Secret");

        // Mallory (who has no documents) searches for "TopSecret" -> receives empty list
        List<Document> malloryResults = documentService.searchAccessibleDocuments("mallory", null, null, "TopSecret", null, null);
        assertThat(malloryResults).isEmpty();

        // When Alice shares her document with Bob, Bob can now see both
        documentShareService.grantAccess(aliceSecret.getId(), "bob", SharePermission.READ, "alice");
        List<Document> bobSharedResults = documentService.searchAccessibleDocuments("bob", null, null, "TopSecret", null, null);
        assertThat(bobSharedResults).extracting(Document::getId).contains(aliceSecret.getId(), bobSecret.getId());

        // Mallory still receives empty list
        assertThat(documentService.searchAccessibleDocuments("mallory", null, null, "TopSecret", null, null)).isEmpty();
    }
}
