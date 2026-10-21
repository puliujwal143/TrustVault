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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Stage 3 Integration Tests: Business-Service Audit Integration.
 *
 * Verifies end-to-end audit trail generation across:
 * 1. DocumentService: DOCUMENT_CREATE, DOCUMENT_READ, DOCUMENT_UPDATE, DOCUMENT_DELETE
 * 2. DocumentShareService: SHARE_GRANT, SHARE_UPDATE, SHARE_REVOKE
 * 3. UserService: USER_DEACTIVATE, USER_REACTIVATE, PASSWORD_CHANGE
 * 4. DocumentAuthorizationService: ACCESS_DENIED on 404 anti-enumeration and 403 forbidden actions
 * 5. Rollback atomicity: failed business mutations roll back SUCCESS audit events
 * 6. Autonomous denial persistence: ACCESS_DENIED events survive authorization failure
 * 7. Query isolation: listing collections does not emit individual audit events
 * 8. Privacy compliance: no credentials, titles, descriptions, or file contents in audit events
 */
@SpringBootTest
class BusinessAuditIntegrationTest {

    @Autowired
    private DocumentService documentService;

    @Autowired
    private DocumentShareService documentShareService;

    @Autowired
    private UserService userService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private DocumentShareRepository documentShareRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private User alice;
    private User bob;
    private User charlie;
    private User disabledUser;

    @BeforeEach
    void setUp() {
        cleanup();
        alice = userService.createUser("alice", "Password123!", "alice@example.com", Role.ROLE_USER);
        bob = userService.createUser("bob", "Password123!", "bob@example.com", Role.ROLE_USER);
        charlie = userService.createUser("charlie", "Password123!", "charlie@example.com", Role.ROLE_USER);
        disabledUser = userService.createUser("disabled_user", "Password123!", "disabled@example.com", Role.ROLE_USER);
        userService.deactivateUser("disabled_user");
        // Clear setup audit events so each test starts with a clean audit log
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
    }

    // =========================================================================
    // 1. DocumentService Audit Integration
    // =========================================================================

    @Test
    @DisplayName("DocumentService.createDocument: records DOCUMENT_CREATE with SUCCESS outcome")
    void createDocument_shouldRecordDocumentCreateEvent() {
        Document doc = documentService.createDocument("Confidential Report", "Annual metrics", "alice");

        List<AuditEvent> events = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(events).hasSize(1);

        AuditEvent event = events.get(0);
        assertThat(event.getAction()).isEqualTo(AuditAction.DOCUMENT_CREATE);
        assertThat(event.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(event.getActorUsername()).isEqualTo("alice");
        assertThat(event.getDocumentId()).isEqualTo(doc.getId());
        assertThat(event.getDocumentStorageKey()).isEqualTo(doc.getStorageKey());
        assertThat(event.getTargetUsername()).isNull();
        // Privacy verification: title and description must not appear in details or any field
        assertThat(event.getDetails()).isNull();
    }

    @Test
    @DisplayName("DocumentService.getDocument: records DOCUMENT_READ only after authorization succeeds")
    void getDocument_shouldRecordDocumentReadOnAuthorizedAccess() {
        Document doc = documentService.createDocument("Project Proposal", "Draft", "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        // Authorized read by owner
        Document retrieved = documentService.getDocument(doc.getId(), "alice");
        assertThat(retrieved).isNotNull();

        List<AuditEvent> events = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(events).hasSize(1);
        AuditEvent readEvent = events.get(0);
        assertThat(readEvent.getAction()).isEqualTo(AuditAction.DOCUMENT_READ);
        assertThat(readEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(readEvent.getDocumentId()).isEqualTo(doc.getId());
        assertThat(readEvent.getDocumentStorageKey()).isEqualTo(doc.getStorageKey());

        // Unauthorized read by unshared user: must NOT record DOCUMENT_READ, must record ACCESS_DENIED
        assertThatThrownBy(() -> documentService.getDocument(doc.getId(), "bob"))
                .isInstanceOf(ResourceNotFoundException.class);

        List<AuditEvent> bobEvents = auditEventRepository.findByActorUsernameOrderByTimestampDesc("bob");
        assertThat(bobEvents).hasSize(1);
        AuditEvent denialEvent = bobEvents.get(0);
        assertThat(denialEvent.getAction()).isEqualTo(AuditAction.ACCESS_DENIED);
        assertThat(denialEvent.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(denialEvent.getDocumentId()).isEqualTo(doc.getId());
        assertThat(denialEvent.getDetails()).contains("NOT_FOUND_OR_UNAUTHORIZED");

        // Verify DOCUMENT_READ count did not increase
        List<AuditEvent> readEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.DOCUMENT_READ);
        assertThat(readEvents).hasSize(1);
    }

    @Test
    @DisplayName("DocumentService.updateDocument: records DOCUMENT_UPDATE with SUCCESS outcome")
    void updateDocument_shouldRecordDocumentUpdateEvent() {
        Document doc = documentService.createDocument("Original Title", "Original Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        Document updated = documentService.updateDocument(doc.getId(), "Updated Title", "Updated Desc", "bob");
        assertThat(updated.getTitle()).isEqualTo("Updated Title");

        List<AuditEvent> bobEvents = auditEventRepository.findByActorUsernameOrderByTimestampDesc("bob");
        assertThat(bobEvents).hasSize(1);
        AuditEvent updateEvent = bobEvents.get(0);
        assertThat(updateEvent.getAction()).isEqualTo(AuditAction.DOCUMENT_UPDATE);
        assertThat(updateEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(updateEvent.getDocumentId()).isEqualTo(doc.getId());
        assertThat(updateEvent.getDocumentStorageKey()).isEqualTo(doc.getStorageKey());
        assertThat(updateEvent.getDetails()).isNull();
    }

    @Test
    @DisplayName("DocumentService.deleteDocument: records DOCUMENT_DELETE and preserves audit history after row deletion")
    void deleteDocument_shouldRecordDocumentDeleteAndPreserveAuditRows() {
        Document doc = documentService.createDocument("Doc to Delete", "Temporary", "alice");
        Long docId = doc.getId();
        var storageKey = doc.getStorageKey();

        documentService.deleteDocument(docId, "alice");

        // Verify document is removed from database
        assertThat(documentRepository.findById(docId)).isEmpty();

        // Verify audit trail retains DOCUMENT_CREATE and DOCUMENT_DELETE with immutable storage key snapshot
        List<AuditEvent> docEvents = auditEventRepository.findByDocumentIdOrderByTimestampDesc(docId);
        assertThat(docEvents).hasSize(2);

        AuditEvent deleteEvent = docEvents.stream()
                .filter(e -> e.getAction() == AuditAction.DOCUMENT_DELETE)
                .findFirst()
                .orElseThrow();
        assertThat(deleteEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(deleteEvent.getDocumentId()).isEqualTo(docId);
        assertThat(deleteEvent.getDocumentStorageKey()).isEqualTo(storageKey);
        assertThat(deleteEvent.getActorUsername()).isEqualTo("alice");
    }

    @Test
    @DisplayName("DocumentService.listAccessibleDocuments: does not record audit events per item")
    void listAccessibleDocuments_shouldNotRecordPerItemAuditEvents() {
        documentService.createDocument("Doc 1", "Desc 1", "alice");
        documentService.createDocument("Doc 2", "Desc 2", "alice");
        documentService.createDocument("Doc 3", "Desc 3", "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        List<Document> accessible = documentService.listAccessibleDocuments("alice");
        assertThat(accessible).hasSize(3);

        List<AuditEvent> events = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(events).isEmpty();
    }

    // =========================================================================
    // 2. DocumentShareService Audit Integration
    // =========================================================================

    @Test
    @DisplayName("DocumentShareService: distinguishes SHARE_GRANT, SHARE_UPDATE, and SHARE_REVOKE")
    void shareLifecycle_shouldDistinguishGrantUpdateAndRevoke() {
        Document doc = documentService.createDocument("Shared Resource", "Team notes", "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        // 1. Initial Grant -> SHARE_GRANT
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        List<AuditEvent> grantEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_GRANT);
        assertThat(grantEvents).hasSize(1);
        AuditEvent grantEvent = grantEvents.get(0);
        assertThat(grantEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(grantEvent.getActorUsername()).isEqualTo("alice");
        assertThat(grantEvent.getTargetUsername()).isEqualTo("bob");
        assertThat(grantEvent.getDocumentId()).isEqualTo(doc.getId());
        assertThat(grantEvent.getDetails()).isEqualTo("permission=READ");

        // 2. Update Grant (READ -> EDIT) -> SHARE_UPDATE
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        List<AuditEvent> updateEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_UPDATE);
        assertThat(updateEvents).hasSize(1);
        AuditEvent updateEvent = updateEvents.get(0);
        assertThat(updateEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(updateEvent.getActorUsername()).isEqualTo("alice");
        assertThat(updateEvent.getTargetUsername()).isEqualTo("bob");
        assertThat(updateEvent.getDocumentId()).isEqualTo(doc.getId());
        assertThat(updateEvent.getDetails()).isEqualTo("permission=EDIT");

        // 3. Revoke Grant -> SHARE_REVOKE
        documentShareService.revokeAccess(doc.getId(), "bob", "alice");

        List<AuditEvent> revokeEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_REVOKE);
        assertThat(revokeEvents).hasSize(1);
        AuditEvent revokeEvent = revokeEvents.get(0);
        assertThat(revokeEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(revokeEvent.getActorUsername()).isEqualTo("alice");
        assertThat(revokeEvent.getTargetUsername()).isEqualTo("bob");
        assertThat(revokeEvent.getDocumentId()).isEqualTo(doc.getId());
    }

    // =========================================================================
    // 3. UserService Audit Integration
    // =========================================================================

    @Test
    @DisplayName("UserService: records USER_DEACTIVATE, USER_REACTIVATE, and PASSWORD_CHANGE")
    void userLifecycle_shouldRecordAccountAndCredentialEvents() {
        // 1. Deactivation
        userService.deactivateUser("charlie");

        List<AuditEvent> deactEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.USER_DEACTIVATE);
        assertThat(deactEvents).hasSize(1);
        AuditEvent deactEvent = deactEvents.get(0);
        assertThat(deactEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(deactEvent.getActorUsername()).isEqualTo("charlie");
        assertThat(deactEvent.getTargetUsername()).isEqualTo("charlie");

        // 2. Reactivation
        userService.reactivateUser("charlie");

        List<AuditEvent> reactEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.USER_REACTIVATE);
        assertThat(reactEvents).hasSize(1);
        AuditEvent reactEvent = reactEvents.get(0);
        assertThat(reactEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(reactEvent.getActorUsername()).isEqualTo("charlie");
        assertThat(reactEvent.getTargetUsername()).isEqualTo("charlie");

        // 3. Password Change
        userService.changePassword("charlie", "Password123!", "NewSecretPass456!");

        List<AuditEvent> pwEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.PASSWORD_CHANGE);
        assertThat(pwEvents).hasSize(1);
        AuditEvent pwEvent = pwEvents.get(0);
        assertThat(pwEvent.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(pwEvent.getActorUsername()).isEqualTo("charlie");
        // Privacy verification: plaintext password must never appear in details or anywhere in event
        assertThat(pwEvent.getDetails()).isNull();
    }

    // =========================================================================
    // 4. Transaction Consistency & Rollback Atomicity
    // =========================================================================

    @Test
    @DisplayName("Rollback atomicity: failed business mutation must roll back its SUCCESS audit event")
    void rollbackAtomicity_shouldRollbackAuditEventWhenMutationFails() {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);

        assertThatThrownBy(() -> tx.execute(status -> {
            documentService.createDocument("Rollback Document", "Will fail", "alice");
            throw new RuntimeException("Simulated business exception forcing rollback");
        })).isInstanceOf(RuntimeException.class);

        // Verify document is not in database
        assertThat(documentRepository.findByOwner(alice)).isEmpty();

        // Verify no DOCUMENT_CREATE event was committed
        List<AuditEvent> events = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(events).isEmpty();
    }

    @Test
    @DisplayName("Rollback atomicity: failed document update rolls back DOCUMENT_UPDATE event")
    void rollbackAtomicity_shouldRollbackUpdateEventWhenUpdateFails() {
        Document doc = documentService.createDocument("Stable Title", "Stable Desc", "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        assertThatThrownBy(() -> tx.execute(status -> {
            documentService.updateDocument(doc.getId(), "Changed Title", "Changed Desc", "alice");
            throw new RuntimeException("Simulated failure after update");
        })).isInstanceOf(RuntimeException.class);

        Document reloaded = documentRepository.findById(doc.getId()).orElseThrow();
        assertThat(reloaded.getTitle()).isEqualTo("Stable Title");

        List<AuditEvent> events = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(events).isEmpty();
    }

    // =========================================================================
    // 5. Authorization Boundary & Security Denial Auditing
    // =========================================================================

    @Test
    @DisplayName("Security denial: nonexistent document request audits ACCESS_DENIED and throws 404")
    void denialAudit_nonexistentDocumentShouldRecordAccessDenied() {
        Long nonexistentId = 88888L;

        assertThatThrownBy(() -> documentService.getDocument(nonexistentId, "alice"))
                .isInstanceOf(ResourceNotFoundException.class);

        List<AuditEvent> denials = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.ACCESS_DENIED);
        assertThat(denials).hasSize(1);
        AuditEvent denial = denials.get(0);
        assertThat(denial.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(denial.getActorUsername()).isEqualTo("alice");
        assertThat(denial.getDocumentId()).isEqualTo(nonexistentId);
        assertThat(denial.getDetails()).contains("NOT_FOUND");
    }

    @Test
    @DisplayName("Security denial: unshared document request audits ACCESS_DENIED and throws 404 anti-enumeration")
    void denialAudit_unsharedDocumentShouldRecordAccessDeniedAndPreserve404() {
        Document doc = documentService.createDocument("Alice Private Vault", "Secret", "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        assertThatThrownBy(() -> documentService.getDocument(doc.getId(), "bob"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Document not found");

        List<AuditEvent> bobDenials = auditEventRepository.findByActorUsernameOrderByTimestampDesc("bob");
        assertThat(bobDenials).hasSize(1);
        AuditEvent denial = bobDenials.get(0);
        assertThat(denial.getAction()).isEqualTo(AuditAction.ACCESS_DENIED);
        assertThat(denial.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(denial.getDocumentId()).isEqualTo(doc.getId());
        assertThat(denial.getDetails()).contains("NOT_FOUND_OR_UNAUTHORIZED");
    }

    @Test
    @DisplayName("Security denial: READ grantee attempting EDIT audits ACCESS_DENIED and throws 403")
    void denialAudit_readGranteeAttemptingEditShouldRecordAccessDeniedAndThrow403() {
        Document doc = documentService.createDocument("Read Only Document", "Notes", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        assertThatThrownBy(() -> documentService.updateDocument(doc.getId(), "Hacked Title", null, "bob"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Insufficient permission");

        List<AuditEvent> bobDenials = auditEventRepository.findByActorUsernameOrderByTimestampDesc("bob");
        assertThat(bobDenials).hasSize(1);
        AuditEvent denial = bobDenials.get(0);
        assertThat(denial.getAction()).isEqualTo(AuditAction.ACCESS_DENIED);
        assertThat(denial.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(denial.getDocumentId()).isEqualTo(doc.getId());
        assertThat(denial.getDetails()).contains("INSUFFICIENT_PERMISSION");
    }

    @Test
    @DisplayName("Security denial: grantee attempting owner-only action (delete) audits ACCESS_DENIED and throws 403")
    void denialAudit_granteeAttemptingOwnerActionShouldRecordAccessDeniedAndThrow403() {
        Document doc = documentService.createDocument("Owner Only Operation", "Notes", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        assertThatThrownBy(() -> documentService.deleteDocument(doc.getId(), "bob"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only the document owner");

        List<AuditEvent> bobDenials = auditEventRepository.findByActorUsernameOrderByTimestampDesc("bob");
        assertThat(bobDenials).hasSize(1);
        AuditEvent denial = bobDenials.get(0);
        assertThat(denial.getAction()).isEqualTo(AuditAction.ACCESS_DENIED);
        assertThat(denial.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(denial.getDocumentId()).isEqualTo(doc.getId());
        assertThat(denial.getDetails()).contains("OWNER_ONLY_OPERATION");
    }

    @Test
    @DisplayName("Security denial: self-grant and disabled grantee are rejected and audited")
    void denialAudit_shareValidationDenials() {
        Document doc = documentService.createDocument("Share Policy Doc", "Notes", "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        // Self-grant rejection
        assertThatThrownBy(() -> documentShareService.grantAccess(doc.getId(), "alice", SharePermission.READ, "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot grant access to themselves");

        // Disabled grantee rejection
        assertThatThrownBy(() -> documentShareService.grantAccess(doc.getId(), "disabled_user", SharePermission.READ, "alice"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Cannot grant access to disabled user");

        List<AuditEvent> aliceEvents = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(aliceEvents).hasSize(2);

        assertThat(aliceEvents).anySatisfy(event -> {
            assertThat(event.getAction()).isEqualTo(AuditAction.ACCESS_DENIED);
            assertThat(event.getOutcome()).isEqualTo(AuditOutcome.DENIED);
            assertThat(event.getDetails()).contains("SELF_GRANT_REJECTED");
        });

        assertThat(aliceEvents).anySatisfy(event -> {
            assertThat(event.getAction()).isEqualTo(AuditAction.ACCESS_DENIED);
            assertThat(event.getOutcome()).isEqualTo(AuditOutcome.DENIED);
            assertThat(event.getTargetUsername()).isEqualTo("disabled_user");
            assertThat(event.getDetails()).contains("DISABLED_GRANTEE_REJECTED");
        });
    }
}
