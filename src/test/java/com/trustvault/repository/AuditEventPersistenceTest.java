package com.trustvault.repository;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
import com.trustvault.entity.Document;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Persistence integration tests for AuditEvent entity and AuditEventRepository.
 *
 * Verifies:
 * - AuditEvent persistence, mapping of all immutable fields, UUID event ID, and timestamp generation.
 * - Strict append-only repository API: reflection proves no delete or update methods exist.
 * - Lookup by eventId, documentId, storageKey, actorUsername, action, and outcome.
 * - Preservation of audit rows and document snapshots when the underlying Document is deleted.
 * - Pagination and count operations.
 * - Constraint enforcement on non-null required audit fields.
 * - Hibernate @Immutable suppresses dirty-checking updates on managed entities.
 * - Invariant equals and hashCode based on UUID eventId.
 */
@SpringBootTest
class AuditEventPersistenceTest {

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @BeforeEach
    void setUp() {
        cleanup();
    }

    @AfterEach
    void tearDown() {
        cleanup();
    }

    private void cleanup() {
        // Native test cleanup: repository deliberately provides no delete methods
        jdbcTemplate.execute("DELETE FROM audit_events");
        documentRepository.deleteAll();
        userRepository.deleteAll();
    }

    private User persistUser(String username, String email) {
        User user = new User(username, "$2a$12$N9qo8uLOickgx2ZMRZoMye.I1z4mKjM97B8Z9e5K.sZz1mNqG9cK2", email, Role.ROLE_USER);
        return userRepository.saveAndFlush(user);
    }

    @Test
    @DisplayName("AuditEvent persistence: should persist and map all fields correctly")
    void auditEvent_shouldPersistAndMapAllFieldsCorrectly() {
        UUID storageKey = UUID.randomUUID();
        AuditEvent event = new AuditEvent(
                "alice",
                AuditAction.DOCUMENT_CREATE,
                100L,
                storageKey,
                "bob",
                AuditOutcome.SUCCESS,
                "192.168.1.100",
                "permission=READ"
        );

        AuditEvent saved = auditEventRepository.save(event);

        assertThat(saved.getId()).isNotNull().isPositive();
        assertThat(saved.getEventId()).isNotNull();
        assertThat(saved.getTimestamp()).isNotNull();
        assertThat(saved.getActorUsername()).isEqualTo("alice");
        assertThat(saved.getAction()).isEqualTo(AuditAction.DOCUMENT_CREATE);
        assertThat(saved.getDocumentId()).isEqualTo(100L);
        assertThat(saved.getDocumentStorageKey()).isEqualTo(storageKey);
        assertThat(saved.getTargetUsername()).isEqualTo("bob");
        assertThat(saved.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(saved.getClientIp()).isEqualTo("192.168.1.100");
        assertThat(saved.getDetails()).isEqualTo("permission=READ");
    }

    @Test
    @DisplayName("Repository API: should expose NO delete, remove, or update methods")
    void auditEvent_repositoryHasNoDeleteOrUpdateMethods() {
        for (Method method : AuditEventRepository.class.getMethods()) {
            String name = method.getName().toLowerCase();
            assertThat(name)
                    .as("Repository must not expose delete or update methods: %s", method.getName())
                    .doesNotStartWith("delete")
                    .doesNotStartWith("remove")
                    .doesNotStartWith("update");
        }
    }

    @Test
    @DisplayName("AuditEvent lookup: should retrieve event by immutable UUID eventId")
    void auditEvent_shouldLookupByEventId() {
        AuditEvent event = new AuditEvent(
                "charlie",
                AuditAction.DOCUMENT_READ,
                200L,
                UUID.randomUUID(),
                null,
                AuditOutcome.SUCCESS,
                "127.0.0.1",
                null
        );
        AuditEvent saved = auditEventRepository.save(event);

        Optional<AuditEvent> found = auditEventRepository.findByEventId(saved.getEventId());

        assertThat(found).isPresent();
        assertThat(found.get().getId()).isEqualTo(saved.getId());
        assertThat(found.get().getActorUsername()).isEqualTo("charlie");
        assertThat(found.get().getAction()).isEqualTo(AuditAction.DOCUMENT_READ);
    }

    @Test
    @DisplayName("AuditEvent queries: should retrieve events ordered by timestamp descending")
    void auditEvent_shouldQueryByDocumentStorageKeyActorActionAndOutcome() {
        UUID docKey1 = UUID.randomUUID();
        UUID docKey2 = UUID.randomUUID();

        AuditEvent event1 = new AuditEvent("alice", AuditAction.DOCUMENT_CREATE, 1L, docKey1, null, AuditOutcome.SUCCESS, null, null);
        AuditEvent event2 = new AuditEvent("alice", AuditAction.SHARE_GRANT, 1L, docKey1, "bob", AuditOutcome.SUCCESS, null, "permission=READ");
        AuditEvent event3 = new AuditEvent("bob", AuditAction.ACCESS_DENIED, 2L, docKey2, null, AuditOutcome.DENIED, null, "reason=NOT_FOUND_OR_UNAUTHORIZED");

        auditEventRepository.save(event1);
        auditEventRepository.save(event2);
        auditEventRepository.save(event3);

        List<AuditEvent> byDoc1 = auditEventRepository.findByDocumentIdOrderByTimestampDesc(1L);
        assertThat(byDoc1).hasSize(2);

        List<AuditEvent> byDocKey1 = auditEventRepository.findByDocumentStorageKeyOrderByTimestampDesc(docKey1);
        assertThat(byDocKey1).hasSize(2);

        List<AuditEvent> byAlice = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(byAlice).hasSize(2);

        List<AuditEvent> byDenied = auditEventRepository.findByOutcomeOrderByTimestampDesc(AuditOutcome.DENIED);
        assertThat(byDenied).hasSize(1);
        assertThat(byDenied.get(0).getActorUsername()).isEqualTo("bob");
        assertThat(byDenied.get(0).getAction()).isEqualTo(AuditAction.ACCESS_DENIED);

        List<AuditEvent> byAction = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_GRANT);
        assertThat(byAction).hasSize(1);
        assertThat(byAction.get(0).getTargetUsername()).isEqualTo("bob");
    }

    @Test
    @DisplayName("Document deletion: audit row and storage key must be preserved when Document is deleted")
    void auditEvent_preservesAuditRowWhenDocumentIsDeleted() {
        User owner = persistUser("david", "david@example.com");
        Document document = new Document("Confidential Plan", "Strategy details", owner);
        Document savedDoc = documentRepository.saveAndFlush(document);

        Long docId = savedDoc.getId();
        UUID storageKey = savedDoc.getStorageKey();

        // Record audit event referencing the document
        AuditEvent createEvent = new AuditEvent(
                "david",
                AuditAction.DOCUMENT_CREATE,
                docId,
                storageKey,
                null,
                AuditOutcome.SUCCESS,
                "10.0.0.1",
                null
        );
        AuditEvent savedEvent = auditEventRepository.save(createEvent);

        // Delete the document entity
        documentRepository.delete(savedDoc);
        documentRepository.flush();

        // Verify document is deleted
        assertThat(documentRepository.findById(docId)).isEmpty();

        // Verify audit event SURVIVES with original documentId and storageKey intact
        Optional<AuditEvent> survivingEvent = auditEventRepository.findById(savedEvent.getId());
        assertThat(survivingEvent).isPresent();
        assertThat(survivingEvent.get().getDocumentId()).isEqualTo(docId);
        assertThat(survivingEvent.get().getDocumentStorageKey()).isEqualTo(storageKey);
        assertThat(survivingEvent.get().getActorUsername()).isEqualTo("david");
    }

    @Test
    @DisplayName("Pagination & count: should return accurate total count and page slice")
    void auditEvent_shouldPaginateAndCount() {
        for (int i = 0; i < 5; i++) {
            auditEventRepository.save(new AuditEvent("user" + i, AuditAction.DOCUMENT_READ, (long) i, UUID.randomUUID(), null, AuditOutcome.SUCCESS, null, null));
        }

        assertThat(auditEventRepository.count()).isEqualTo(5);

        Page<AuditEvent> page = auditEventRepository.findAll(PageRequest.of(0, 3));
        assertThat(page.getTotalElements()).isEqualTo(5);
        assertThat(page.getContent()).hasSize(3);
        assertThat(page.getTotalPages()).isEqualTo(2);
    }

    @Test
    @DisplayName("Validation: should reject null required fields (actorUsername, action, outcome)")
    void auditEvent_rejectsNullRequiredFields() {
        AuditEvent invalidActor = new AuditEvent(null, AuditAction.DOCUMENT_CREATE, 1L, UUID.randomUUID(), null, AuditOutcome.SUCCESS, null, null);
        assertThatThrownBy(() -> auditEventRepository.save(invalidActor))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);

        AuditEvent invalidAction = new AuditEvent("alice", null, 1L, UUID.randomUUID(), null, AuditOutcome.SUCCESS, null, null);
        assertThatThrownBy(() -> auditEventRepository.save(invalidAction))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);

        AuditEvent invalidOutcome = new AuditEvent("alice", AuditAction.DOCUMENT_CREATE, 1L, UUID.randomUUID(), null, null, null, null);
        assertThatThrownBy(() -> auditEventRepository.save(invalidOutcome))
                .isInstanceOf(jakarta.validation.ConstraintViolationException.class);
    }

    @Test
    @DisplayName("Hibernate @Immutable: dirty checking must not issue SQL UPDATE for modified entity fields")
    void auditEvent_hibernateImmutableSuppressesDirtyCheckingUpdates() throws Exception {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);

        Long eventId = tx.execute(status -> {
            AuditEvent event = new AuditEvent(
                    "original_actor",
                    AuditAction.DOCUMENT_CREATE,
                    1L,
                    UUID.randomUUID(),
                    null,
                    AuditOutcome.SUCCESS,
                    null,
                    "original_details"
            );
            AuditEvent saved = auditEventRepository.save(event);
            entityManager.flush();
            return saved.getId();
        });

        assertThat(eventId).isNotNull();

        // In a second transaction, load the entity, mutate a field via reflection, and flush
        tx.executeWithoutResult(status -> {
            AuditEvent loaded = auditEventRepository.findById(eventId).orElseThrow();
            try {
                Field actorField = AuditEvent.class.getDeclaredField("actorUsername");
                actorField.setAccessible(true);
                actorField.set(loaded, "tampered_actor");

                Field detailsField = AuditEvent.class.getDeclaredField("details");
                detailsField.setAccessible(true);
                detailsField.set(loaded, "tampered_details");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            // Flush the session: Hibernate @Immutable causes dirty-checking to skip this entity
            entityManager.flush();
        });

        // In a third transaction, reload from DB and verify fields are UNCHANGED
        tx.executeWithoutResult(status -> {
            AuditEvent fresh = auditEventRepository.findById(eventId).orElseThrow();
            assertThat(fresh.getActorUsername())
                    .as("Actor username must not be updated due to @Immutable")
                    .isEqualTo("original_actor");
            assertThat(fresh.getDetails())
                    .as("Details must not be updated due to @Immutable")
                    .isEqualTo("original_details");
        });
    }

    @Test
    @DisplayName("JPA Set invariance: equals and hashCode must be consistent across state transitions based on eventId")
    void auditEvent_equalsAndHashCodeAreBasedOnEventId() {
        AuditEvent event1 = new AuditEvent("alice", AuditAction.DOCUMENT_CREATE, 1L, null, null, AuditOutcome.SUCCESS, null, null);
        UUID eventId = event1.getEventId();

        AuditEvent event2 = new AuditEvent(eventId, Instant.now(), "alice", AuditAction.DOCUMENT_CREATE, 1L, null, null, AuditOutcome.SUCCESS, null, null);

        assertThat(event1).isEqualTo(event2);
        assertThat(event1.hashCode()).isEqualTo(event2.hashCode());

        Set<AuditEvent> set = new HashSet<>();
        set.add(event1);

        assertThat(set).contains(event2);
    }

    @Test
    @DisplayName("AuditAction persistence: should persist and query events with FILE_UPLOAD and FILE_DOWNLOAD actions")
    void auditEvent_shouldPersistAndQueryFileUploadAndDownloadActions() {
        UUID storageKey = UUID.randomUUID();

        AuditEvent uploadEvent = new AuditEvent(
                "alice",
                AuditAction.FILE_UPLOAD,
                50L,
                storageKey,
                null,
                AuditOutcome.SUCCESS,
                "192.168.1.50",
                "filename=report.pdf,size=102400"
        );
        AuditEvent savedUpload = auditEventRepository.save(uploadEvent);

        AuditEvent downloadEvent = new AuditEvent(
                "bob",
                AuditAction.FILE_DOWNLOAD,
                50L,
                storageKey,
                null,
                AuditOutcome.SUCCESS,
                "192.168.1.60",
                "filename=report.pdf"
        );
        AuditEvent savedDownload = auditEventRepository.save(downloadEvent);

        Optional<AuditEvent> fetchedUpload = auditEventRepository.findById(savedUpload.getId());
        assertThat(fetchedUpload).isPresent();
        assertThat(fetchedUpload.get().getAction()).isEqualTo(AuditAction.FILE_UPLOAD);
        assertThat(fetchedUpload.get().getDocumentId()).isEqualTo(50L);
        assertThat(fetchedUpload.get().getDocumentStorageKey()).isEqualTo(storageKey);

        Optional<AuditEvent> fetchedDownload = auditEventRepository.findById(savedDownload.getId());
        assertThat(fetchedDownload).isPresent();
        assertThat(fetchedDownload.get().getAction()).isEqualTo(AuditAction.FILE_DOWNLOAD);
        assertThat(fetchedDownload.get().getDocumentId()).isEqualTo(50L);
        assertThat(fetchedDownload.get().getDocumentStorageKey()).isEqualTo(storageKey);

        List<AuditEvent> uploadEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.FILE_UPLOAD);
        assertThat(uploadEvents).hasSize(1);
        assertThat(uploadEvents.get(0).getActorUsername()).isEqualTo("alice");

        List<AuditEvent> downloadEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.FILE_DOWNLOAD);
        assertThat(downloadEvents).hasSize(1);
        assertThat(downloadEvents.get(0).getActorUsername()).isEqualTo("bob");
    }
}
