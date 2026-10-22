package com.trustvault.controller;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditOutcome;
import com.trustvault.dto.AuditItemViewModel;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.repository.AuditEventRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.AuditService;
import com.trustvault.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Integration tests for the Audit History view:
 * {@code GET /audit}.
 *
 * Verifies:
 * - Unauthenticated request is redirected to /login (reproducing and verifying fix for prior 404).
 * - Authenticated user can view their audit history page with HTTP 200 OK.
 * - Non-admin user can only view their own audit events.
 * - Non-admin user attempting URL parameter tampering (?actor=other) is rejected with HTTP 403 Forbidden.
 * - Admin user with ROLE_ADMIN can view all events or filter by actor.
 * - Displays safe audit fields: action label, outcome badge, timestamp, actor, document reference.
 * - Strictly suppresses sensitive blob storage keys, filesystem paths, and secrets.
 * - Pagination handles multi-page datasets with correct navigation controls.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuditViewControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditService auditService;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private DocumentShareRepository documentShareRepository;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private User alice;
    private User bob;
    private User admin;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("DELETE FROM audit_events");
        documentShareRepository.deleteAll();
        documentRepository.deleteAll();
        userRepository.deleteAll();

        alice = userService.createUser("alice", "Password123!", "alice@example.com", Role.ROLE_USER);
        bob = userService.createUser("bob", "Password123!", "bob@example.com", Role.ROLE_USER);
        admin = userService.createUser("admin", "Password123!", "admin@example.com", Role.ROLE_ADMIN);
    }

    @Test
    @DisplayName("GET /audit: unauthenticated request is redirected to /login (fixes prior 404 failure)")
    void testAuditUnauthenticatedRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/audit").accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("GET /audit: unauthenticated request without HTML accept header returns 401 Unauthorized")
    void testAuditUnauthenticatedWithoutAcceptHeaderReturns401() throws Exception {
        mockMvc.perform(get("/audit"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /audit: real form-login session loads audit page successfully")
    void testAuditWithRealFormLoginSession() throws Exception {
        MvcResult loginResult = mockMvc.perform(
                org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin()
                        .user("alice")
                        .password("Password123!"))
                .andExpect(status().isFound())
                .andReturn();

        org.springframework.mock.web.MockHttpSession session =
                (org.springframework.mock.web.MockHttpSession) loginResult.getRequest().getSession();

        mockMvc.perform(get("/audit").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("audit/list"))
                .andExpect(content().string(containsString("Audit History")));
    }

    @Test
    @DisplayName("GET /audit: devuser with ROLE_USER loads audit page successfully without parameters")
    void testAuditDevUserLoadsSuccessfullyWithoutParameters() throws Exception {
        userService.createUser("devuser", "Password123!", "devuser@example.com", Role.ROLE_USER);
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "devuser", 999L, UUID.randomUUID(), null, null, null);

        mockMvc.perform(get("/audit").with(user("devuser").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(view().name("audit/list"))
                .andExpect(model().attribute("totalCount", 1L))
                .andExpect(model().attribute("selectedActor", "devuser"))
                .andExpect(content().string(containsString("#999")));
    }

    @Test
    @DisplayName("GET /audit: authenticated user loads audit page successfully with empty state")
    void testAuditAuthenticatedUserLoadsSuccessfullyWithEmptyState() throws Exception {
        mockMvc.perform(get("/audit").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("audit/list"))
                .andExpect(model().attributeExists("events"))
                .andExpect(model().attribute("totalCount", 0L))
                .andExpect(model().attribute("activeTab", "audit"))
                .andExpect(content().string(containsString("Audit History")))
                .andExpect(content().string(containsString("id=\"audit-empty-state\"")))
                .andExpect(content().string(containsString("No audit records found")));
    }

    @Test
    @DisplayName("GET /audit: renders audit event metadata safely without exposing storage keys or physical paths")
    void testAuditRendersEventMetadataSafelyWithoutSecrets() throws Exception {
        UUID storageKey = UUID.randomUUID();
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "alice", 101L, storageKey, null, "192.168.1.10", null);
        auditService.recordSuccess(AuditAction.FILE_UPLOAD, "alice", 101L, storageKey, null, "192.168.1.10", "QuarterlyReport.pdf");
        auditService.recordSecurityDenial("alice", 102L, storageKey, null, "192.168.1.10", "reason=NOT_FOUND_OR_UNAUTHORIZED");

        MvcResult result = mockMvc.perform(get("/audit").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("audit/list"))
                .andExpect(model().attributeExists("events"))
                .andExpect(content().string(containsString("Document Created")))
                .andExpect(content().string(containsString("File Uploaded")))
                .andExpect(content().string(containsString("Access Denied")))
                .andExpect(content().string(containsString("SUCCESS")))
                .andExpect(content().string(containsString("DENIED")))
                .andExpect(content().string(containsString("#101")))
                .andExpect(content().string(containsString("QuarterlyReport.pdf")))
                // Strict check: storage key UUID must NEVER be leaked in the HTML response
                .andExpect(content().string(not(containsString(storageKey.toString()))))
                .andReturn();

        @SuppressWarnings("unchecked")
        List<AuditItemViewModel> events = (List<AuditItemViewModel>) result.getModelAndView().getModel().get("events");
        assertThat(events).hasSize(3);
    }

    @Test
    @DisplayName("GET /audit: standard user only sees their own events and cannot see other users' events")
    void testAuditStandardUserOnlySeesOwnEvents() throws Exception {
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "alice", 201L, UUID.randomUUID(), null, null, null);
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "bob", 202L, UUID.randomUUID(), null, null, null);

        mockMvc.perform(get("/audit").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("#201")))
                .andExpect(content().string(not(containsString("#202"))));
    }

    @Test
    @DisplayName("GET /audit?actor=bob: standard user attempting parameter tampering is rejected with 403 Forbidden")
    void testAuditNonAdminCannotViewOtherUsersAuditViaParameterTampering() throws Exception {
        mockMvc.perform(get("/audit")
                        .param("actor", "bob")
                        .with(user("alice")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /audit: admin with ROLE_ADMIN can view all events across the platform")
    void testAuditAdminCanViewAllEvents() throws Exception {
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "alice", 301L, UUID.randomUUID(), null, null, null);
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "bob", 302L, UUID.randomUUID(), null, null, null);

        mockMvc.perform(get("/audit").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("#301")))
                .andExpect(content().string(containsString("#302")));
    }

    @Test
    @DisplayName("GET /audit?actor=alice: admin can filter events by actor")
    void testAuditAdminCanFilterByActor() throws Exception {
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "alice", 401L, UUID.randomUUID(), null, null, null);
        auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "bob", 402L, UUID.randomUUID(), null, null, null);

        mockMvc.perform(get("/audit")
                        .param("actor", "alice")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("#401")))
                .andExpect(content().string(not(containsString("#402"))));
    }

    @Test
    @DisplayName("GET /audit: pagination handles multiple pages and displays navigation controls")
    void testAuditPagination() throws Exception {
        for (int i = 1; i <= 25; i++) {
            auditService.recordSuccess(AuditAction.DOCUMENT_CREATE, "alice", (long) i, UUID.randomUUID(), null, null, "Doc " + i);
        }

        // Page 0 (size 10)
        MvcResult page0Result = mockMvc.perform(get("/audit")
                        .param("page", "0")
                        .param("size", "10")
                        .with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(model().attribute("currentPage", 0))
                .andExpect(model().attribute("totalPages", 3))
                .andExpect(model().attribute("totalElements", 25L))
                .andExpect(model().attribute("hasNext", true))
                .andExpect(model().attribute("hasPrevious", false))
                .andExpect(content().string(containsString("id=\"audit-next-page-btn\"")))
                .andExpect(content().string(containsString("Showing page <strong>1</strong> of <strong>3</strong>")))
                .andReturn();

        @SuppressWarnings("unchecked")
        List<AuditItemViewModel> page0Events = (List<AuditItemViewModel>) page0Result.getModelAndView().getModel().get("events");
        assertThat(page0Events).hasSize(10);

        // Page 1 (size 10)
        MvcResult page1Result = mockMvc.perform(get("/audit")
                        .param("page", "1")
                        .param("size", "10")
                        .with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(model().attribute("currentPage", 1))
                .andExpect(model().attribute("hasNext", true))
                .andExpect(model().attribute("hasPrevious", true))
                .andExpect(content().string(containsString("id=\"audit-prev-page-btn\"")))
                .andExpect(content().string(containsString("id=\"audit-next-page-btn\"")))
                .andReturn();

        @SuppressWarnings("unchecked")
        List<AuditItemViewModel> page1Events = (List<AuditItemViewModel>) page1Result.getModelAndView().getModel().get("events");
        assertThat(page1Events).hasSize(10);
    }
}
