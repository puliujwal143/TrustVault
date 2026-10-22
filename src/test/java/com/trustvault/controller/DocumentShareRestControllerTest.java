package com.trustvault.controller;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.Role;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.repository.AuditEventRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.DocumentService;
import com.trustvault.service.DocumentShareService;
import com.trustvault.service.UserService;
import com.trustvault.storage.StorageService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for document sharing REST API endpoints:
 * - POST /api/documents/{id}/shares
 * - DELETE /api/documents/{id}/shares/{granteeUsername}
 * - GET /api/documents/{id}/shares
 */
@SpringBootTest
@AutoConfigureMockMvc
class DocumentShareRestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private DocumentShareService documentShareService;

    @Autowired
    private UserService userService;

    @Autowired
    private StorageService storageService;

    @Autowired
    private DocumentRepository documentRepository;

    @Autowired
    private DocumentShareRepository documentShareRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private User alice;
    private User bob;
    private User admin;

    @BeforeEach
    void setUp() {
        if (storageService != null) {
            storageService.deleteAll();
        }
        jdbcTemplate.execute("DELETE FROM audit_events");
        documentShareRepository.deleteAll();
        documentRepository.deleteAll();
        userRepository.deleteAll();

        alice = userService.createUser("alice", "Password123!", "alice@example.com", Role.ROLE_USER);
        bob = userService.createUser("bob", "Password123!", "bob@example.com", Role.ROLE_USER);
        admin = userService.createUser("admin", "Password123!", "admin@example.com", Role.ROLE_ADMIN);
    }

    @AfterEach
    void tearDown() {
        if (storageService != null) {
            storageService.deleteAll();
        }
    }

    @Test
    @DisplayName("POST /api/documents/{id}/shares: owner grants READ share returns 200 OK and response DTO")
    void testOwnerGrantsReadShareSuccess() throws Exception {
        Document doc = documentService.createDocument("API Share Doc", "Desc", "alice");

        mockMvc.perform(post("/api/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "READ")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.granteeUsername", is("bob")))
                .andExpect(jsonPath("$.permission", is("READ")))
                .andExpect(jsonPath("$.documentId", is(doc.getId().intValue())));

        List<DocumentShare> shares = documentShareRepository.findByDocumentId(doc.getId());
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getPermission()).isEqualTo(SharePermission.READ);

        List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_GRANT);
        assertThat(events).anyMatch(e -> "alice".equals(e.getActorUsername()) && "bob".equals(e.getTargetUsername()));
    }

    @Test
    @DisplayName("POST /api/documents/{id}/shares: owner grants EDIT share returns 200 OK")
    void testOwnerGrantsEditShareSuccess() throws Exception {
        Document doc = documentService.createDocument("API Share Edit Doc", "Desc", "alice");

        mockMvc.perform(post("/api/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "EDIT")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.granteeUsername", is("bob")))
                .andExpect(jsonPath("$.permission", is("EDIT")));

        List<DocumentShare> shares = documentShareRepository.findByDocumentId(doc.getId());
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getPermission()).isEqualTo(SharePermission.EDIT);
    }

    @Test
    @DisplayName("GET /api/documents/{id}/shares: owner lists active shares")
    void testOwnerListsSharesSuccess() throws Exception {
        Document doc = documentService.createDocument("API List Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(get("/api/documents/" + doc.getId() + "/shares")
                        .with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].granteeUsername", is("bob")))
                .andExpect(jsonPath("$[0].permission", is("READ")));
    }

    @Test
    @DisplayName("DELETE /api/documents/{id}/shares/{username}: owner revokes share returns 204 No Content")
    void testOwnerRevokesShareSuccess() throws Exception {
        Document doc = documentService.createDocument("API Revoke Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(delete("/api/documents/" + doc.getId() + "/shares/bob")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isNoContent());

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).isEmpty();
    }

    @Test
    @DisplayName("POST /api/documents/{id}/shares: unshared user receives 404 Not Found (anti-IDOR)")
    void testUnsharedUserCannotShareApi() throws Exception {
        Document doc = documentService.createDocument("API Anti-IDOR Doc", "Desc", "alice");

        mockMvc.perform(post("/api/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "READ")
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /api/documents/{id}/shares: collaborator receives 403 Forbidden")
    void testCollaboratorCannotShareApi() throws Exception {
        Document doc = documentService.createDocument("API Forbidden Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        mockMvc.perform(post("/api/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "admin")
                        .param("permission", "READ")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("DELETE /api/documents/{id}/shares/{username}: collaborator receives 403 Forbidden")
    void testCollaboratorCannotRevokeApi() throws Exception {
        Document doc = documentService.createDocument("API Collab Revoke Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");
        User carol = userService.createUser("carol", "Password123!", "carol@example.com", Role.ROLE_USER);
        documentShareService.grantAccess(doc.getId(), "carol", SharePermission.EDIT, "alice");

        mockMvc.perform(delete("/api/documents/" + doc.getId() + "/shares/bob")
                        .with(user("carol"))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /api/documents/{id}/shares: missing CSRF token returns 403 Forbidden")
    void testShareWithoutCsrfRejected() throws Exception {
        Document doc = documentService.createDocument("API CSRF Doc", "Desc", "alice");

        mockMvc.perform(post("/api/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "READ")
                        .with(user("alice")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("DELETE /api/documents/{id}/shares/{username}: missing CSRF token returns 403 Forbidden")
    void testRevokeWithoutCsrfRejected() throws Exception {
        Document doc = documentService.createDocument("API Revoke CSRF Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(delete("/api/documents/" + doc.getId() + "/shares/bob")
                        .with(user("alice")))
                .andExpect(status().isForbidden());
    }
}
