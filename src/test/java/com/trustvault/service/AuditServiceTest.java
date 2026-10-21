package com.trustvault.service;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
import com.trustvault.repository.AuditEventRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for AuditService transaction consistency and security-denial logging.
 *
 * Verifies:
 * - Successful business audit events commit with the business transaction.
 * - Rollback of a business transaction rolls back its corresponding SUCCESS audit event.
 * - Security denial events (REQUIRES_NEW) survive the rollback of the outer transaction.
 * - Standalone denial recording without an active outer transaction.
 * - Input validation, string sanitization, and length bounding.
 * - Read-only querying and pagination of audit logs.
 */
@SpringBootTest
class AuditServiceTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        cleanup();
    }

    @AfterEach
    void tearDown() {
        cleanup();
    }

    private void cleanup() {
        jdbcTemplate.execute("DELETE FROM audit_events");
    }

    @Test
    @DisplayName("recordSuccess: should persist audit event with SUCCESS outcome")
    void recordSuccess_shouldPersistEventInCurrentTransaction() {
        UUID storageKey = UUID.randomUUID();

        AuditEvent event = auditService.recordSuccess(
                AuditAction.DOCUMENT_CREATE,
                "alice",
                10L,
                storageKey,
                null,
                "192.168.1.1",
                "title_hash=none"
        );

        assertThat(event.getId()).isNotNull();
        assertThat(event.getAction()).isEqualTo(AuditAction.DOCUMENT_CREATE);
        assertThat(event.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(event.getActorUsername()).isEqualTo("alice");
        assertThat(event.getDocumentId()).isEqualTo(10L);
        assertThat(event.getDocumentStorageKey()).isEqualTo(storageKey);
        assertThat(event.getClientIp()).isEqualTo("192.168.1.1");
        assertThat(event.getDetails()).isEqualTo("title_hash=none");

        Optional<AuditEvent> found = auditService.getEventById(event.getId());
        assertThat(found).isPresent();
    }

    @Test
    @DisplayName("Transaction consistency: business transaction rollback must roll back SUCCESS audit event")
    void recordSuccess_shouldRollbackWhenBusinessTransactionRollsBack() {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);

        assertThatThrownBy(() -> tx.execute(status -> {
            // Record a SUCCESS audit event in this transaction
            auditService.recordSuccess(
                    AuditAction.DOCUMENT_CREATE,
                    "bob",
                    20L,
                    UUID.randomUUID(),
                    null,
                    "10.0.0.1",
                    null
            );

            // Simulate business transaction failure causing rollback
            throw new RuntimeException("Simulated business mutation failure");
        })).isInstanceOf(RuntimeException.class)
                .hasMessage("Simulated business mutation failure");

        // Verify that NO SUCCESS audit event exists in the database
        assertThat(auditService.getEventCount()).isZero();
        assertThat(auditService.getEventsForActor("bob")).isEmpty();
    }

    @Test
    @DisplayName("Security denial logging: denial event in REQUIRES_NEW must survive outer transaction rollback")
    void recordSecurityDenial_inNewTransaction_shouldSurviveOuterTransactionRollback() {
        TransactionTemplate tx = new TransactionTemplate(transactionManager);
        UUID storageKey = UUID.randomUUID();

        assertThatThrownBy(() -> tx.execute(status -> {
            // Inside active outer transaction, record an unauthorized access attempt
            auditService.recordSecurityDenial(
                    "intruder",
                    30L,
                    storageKey,
                    null,
                    "203.0.113.5",
                    "reason=NOT_FOUND_OR_UNAUTHORIZED"
            );

            // Outer transaction fails with authorization exception
            throw new AccessDeniedException("Access denied to document 30");
        })).isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access denied to document 30");

        // Outer transaction rolled back, but the denial audit event MUST have committed and survived
        List<AuditEvent> denials = auditService.getEventsByAction(AuditAction.ACCESS_DENIED);
        assertThat(denials).hasSize(1);

        AuditEvent denialEvent = denials.get(0);
        assertThat(denialEvent.getActorUsername()).isEqualTo("intruder");
        assertThat(denialEvent.getDocumentId()).isEqualTo(30L);
        assertThat(denialEvent.getDocumentStorageKey()).isEqualTo(storageKey);
        assertThat(denialEvent.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(denialEvent.getClientIp()).isEqualTo("203.0.113.5");
        assertThat(denialEvent.getDetails()).isEqualTo("reason=NOT_FOUND_OR_UNAUTHORIZED");
    }

    @Test
    @DisplayName("recordSecurityDenial: should persist denial event in standalone context without outer transaction")
    void recordSecurityDenial_standalone_shouldPersistWithoutOuterTransaction() {
        Optional<AuditEvent> result = auditService.recordSecurityDenial(
                "mallory",
                40L,
                null,
                "victim",
                "198.51.100.2",
                "reason=INSUFFICIENT_PERMISSION"
        );

        assertThat(result).isPresent();
        AuditEvent event = result.get();
        assertThat(event.getId()).isNotNull();
        assertThat(event.getActorUsername()).isEqualTo("mallory");
        assertThat(event.getAction()).isEqualTo(AuditAction.ACCESS_DENIED);
        assertThat(event.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(event.getTargetUsername()).isEqualTo("victim");
    }

    @Test
    @DisplayName("recordSecurityDenial: should use ANONYMOUS if actor username is null or blank")
    void recordSecurityDenial_shouldUseAnonymousForNullActor() {
        Optional<AuditEvent> result = auditService.recordSecurityDenial(
                null,
                50L,
                null,
                null,
                "127.0.0.1",
                "reason=UNAUTHENTICATED"
        );

        assertThat(result).isPresent();
        assertThat(result.get().getActorUsername()).isEqualTo("ANONYMOUS");
    }

    @Test
    @DisplayName("Validation: recordEvent must reject null action, null outcome, or blank actor")
    void recordEvent_validation_shouldRejectNullActorOrActionOrOutcome() {
        assertThatThrownBy(() -> auditService.recordEvent(
                null,
                AuditOutcome.SUCCESS,
                "alice",
                null, null, null, null, null
        )).isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> auditService.recordEvent(
                AuditAction.DOCUMENT_CREATE,
                null,
                "alice",
                null, null, null, null, null
        )).isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> auditService.recordEvent(
                AuditAction.DOCUMENT_CREATE,
                AuditOutcome.SUCCESS,
                "   ",
                null, null, null, null, null
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Sanitization: should normalize control characters and length-bound string fields")
    void sanitization_shouldTrimControlCharsAndBoundLength() {
        String longActor = "user\nwith\rnewlines\tand_very_long_name_exceeding_fifty_characters_total";
        String longDetails = "a".repeat(600);

        AuditEvent event = auditService.recordSuccess(
                AuditAction.DOCUMENT_UPDATE,
                longActor,
                1L,
                UUID.randomUUID(),
                "target\nuser",
                "127.0.0.1\n",
                longDetails
        );

        assertThat(event.getActorUsername())
                .doesNotContain("\n", "\r", "\t")
                .hasSizeLessThanOrEqualTo(50);

        assertThat(event.getTargetUsername())
                .doesNotContain("\n")
                .isEqualTo("target user");

        assertThat(event.getClientIp())
                .doesNotContain("\n")
                .isEqualTo("127.0.0.1");

        assertThat(event.getDetails())
                .hasSize(500);
    }

    @Test
    @DisplayName("Query methods: should retrieve audit trails by document, actor, action, and pagination")
    void readMethods_shouldRetrieveChronologicalHistory() {
        UUID key1 = UUID.randomUUID();
        UUID key2 = UUID.randomUUID();

        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "alice", 100L, key1, null, null, null);
        auditService.recordSuccess(AuditAction.SHARE_GRANT, "alice", 100L, key1, "bob", null, "permission=READ");
        auditService.recordSuccess(AuditAction.DOCUMENT_READ, "bob", 100L, key1, null, null, null);
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "carol", 200L, key2, null, null, null);

        // Document filter
        List<AuditEvent> doc1Events = auditService.getEventsForDocument(100L);
        assertThat(doc1Events).hasSize(3);

        List<AuditEvent> docKey1Events = auditService.getEventsForDocumentStorageKey(key1);
        assertThat(docKey1Events).hasSize(3);

        // Actor filter
        List<AuditEvent> aliceEvents = auditService.getEventsForActor("alice");
        assertThat(aliceEvents).hasSize(2);

        // Action filter
        List<AuditEvent> createEvents = auditService.getEventsByAction(AuditAction.DOCUMENT_CREATE);
        assertThat(createEvents).hasSize(2);

        // Outcome filter
        List<AuditEvent> successEvents = auditService.getEventsByOutcome(AuditOutcome.SUCCESS);
        assertThat(successEvents).hasSize(4);

        // Pagination & count
        assertThat(auditService.getEventCount()).isEqualTo(4);

        Page<AuditEvent> page = auditService.getAllEvents(PageRequest.of(0, 2));
        assertThat(page.getTotalElements()).isEqualTo(4);
        assertThat(page.getContent()).hasSize(2);
        assertThat(page.getTotalPages()).isEqualTo(2);

        // EventId lookup
        UUID firstEventId = doc1Events.get(0).getEventId();
        Optional<AuditEvent> byEventId = auditService.getEventByEventId(firstEventId);
        assertThat(byEventId).isPresent();
    }
}
