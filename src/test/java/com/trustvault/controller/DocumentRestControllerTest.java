package com.trustvault.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.dto.CreateDocumentForm;
import com.trustvault.dto.UpdateDocumentForm;
import com.trustvault.entity.Document;
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
import org.springframework.http.MediaType;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class DocumentRestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

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

    // =========================================================================
    // Document Creation Tests (POST /api/documents)
    // =========================================================================

    @Test
    @DisplayName("POST /api/documents: authenticated user creates document successfully")
    void testCreateDocumentSuccess() throws Exception {
        CreateDocumentForm request = new CreateDocumentForm("Q4 Earnings", "Financial statement");

        mockMvc.perform(post("/api/documents")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title", is("Q4 Earnings")))
                .andExpect(jsonPath("$.description", is("Financial statement")))
                .andExpect(jsonPath("$.ownerUsername", is("alice")));
    }

    @Test
    @DisplayName("POST /api/documents: unauthenticated request is rejected with 401")
    void testCreateDocumentUnauthenticated() throws Exception {
        CreateDocumentForm request = new CreateDocumentForm("Q4 Earnings", "Financial statement");

        mockMvc.perform(post("/api/documents")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    // =========================================================================
    // Document Retrieval Tests (GET /api/documents/{id})
    // =========================================================================

    @Test
    @DisplayName("GET /api/documents/{id}: owner can retrieve document")
    void testGetDocumentAsOwner() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Details", "alice");

        mockMvc.perform(get("/api/documents/" + doc.getId()).with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(doc.getId().intValue())))
                .andExpect(jsonPath("$.title", is("Alice Doc")));
    }

    @Test
    @DisplayName("GET /api/documents/{id}: READ collaborator can retrieve document")
    void testGetDocumentAsReadCollaborator() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Details", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(get("/api/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title", is("Alice Doc")));
    }

    @Test
    @DisplayName("GET /api/documents/{id}: unshared user receives 404 anti-IDOR")
    void testGetDocumentAsUnsharedUser() throws Exception {
        Document doc = documentService.createDocument("Alice Secret", "Details", "alice");

        mockMvc.perform(get("/api/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isNotFound());
    }

    // =========================================================================
    // Document Update Tests (PUT /api/documents/{id})
    // =========================================================================

    @Test
    @DisplayName("PUT /api/documents/{id}: owner can update document metadata")
    void testUpdateDocumentAsOwner() throws Exception {
        Document doc = documentService.createDocument("Initial Title", "Initial Desc", "alice");
        UpdateDocumentForm req = new UpdateDocumentForm("Modified Title", "Modified Desc");

        mockMvc.perform(put("/api/documents/" + doc.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req))
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title", is("Modified Title")))
                .andExpect(jsonPath("$.description", is("Modified Desc")));

        Document updated = documentRepository.findById(doc.getId()).orElseThrow();
        assertThat(updated.getTitle()).isEqualTo("Modified Title");
    }

    @Test
    @DisplayName("PUT /api/documents/{id}: EDIT collaborator can update document metadata")
    void testUpdateDocumentAsEditCollaborator() throws Exception {
        Document doc = documentService.createDocument("Shared Doc", "Initial", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        UpdateDocumentForm req = new UpdateDocumentForm("Updated by Bob", "New Desc");

        mockMvc.perform(put("/api/documents/" + doc.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req))
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title", is("Updated by Bob")));
    }

    @Test
    @DisplayName("PUT /api/documents/{id}: READ collaborator cannot update document (403 Forbidden)")
    void testUpdateDocumentAsReadCollaboratorDenied() throws Exception {
        Document doc = documentService.createDocument("Shared Doc", "Initial", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        UpdateDocumentForm req = new UpdateDocumentForm("Tampered", "Desc");

        mockMvc.perform(put("/api/documents/" + doc.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req))
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("PUT /api/documents/{id}: unshared user receives 404 anti-IDOR")
    void testUpdateDocumentAsUnsharedUserDenied() throws Exception {
        Document doc = documentService.createDocument("Private Doc", "Initial", "alice");
        UpdateDocumentForm req = new UpdateDocumentForm("Tampered", "Desc");

        mockMvc.perform(put("/api/documents/" + doc.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req))
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("PUT /api/documents/{id}: blank title is rejected with 400 Bad Request")
    void testUpdateDocumentBlankTitleValidation() throws Exception {
        Document doc = documentService.createDocument("Valid Doc", "Initial", "alice");
        UpdateDocumentForm req = new UpdateDocumentForm("   ", "Desc");

        mockMvc.perform(put("/api/documents/" + doc.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req))
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    // =========================================================================
    // Document Deletion Tests (DELETE /api/documents/{id})
    // =========================================================================

    @Test
    @DisplayName("DELETE /api/documents/{id}: owner can delete document (204 No Content)")
    void testDeleteDocumentAsOwner() throws Exception {
        Document doc = documentService.createDocument("Doc to Delete", "Initial", "alice");

        mockMvc.perform(delete("/api/documents/" + doc.getId())
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isNoContent());

        assertThat(documentRepository.findById(doc.getId())).isEmpty();

        List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.DOCUMENT_DELETE);
        assertThat(events).anyMatch(e -> "alice".equals(e.getActorUsername()) && doc.getId().equals(e.getDocumentId()));
    }

    @Test
    @DisplayName("DELETE /api/documents/{id}: EDIT collaborator cannot delete document (403 Forbidden)")
    void testDeleteDocumentAsEditCollaboratorDenied() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Initial", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        mockMvc.perform(delete("/api/documents/" + doc.getId())
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        assertThat(documentRepository.findById(doc.getId())).isPresent();
    }

    @Test
    @DisplayName("DELETE /api/documents/{id}: READ collaborator cannot delete document (403 Forbidden)")
    void testDeleteDocumentAsReadCollaboratorDenied() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Initial", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(delete("/api/documents/" + doc.getId())
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        assertThat(documentRepository.findById(doc.getId())).isPresent();
    }

    @Test
    @DisplayName("DELETE /api/documents/{id}: unshared user receives 404 anti-IDOR")
    void testDeleteDocumentAsUnsharedUserDenied() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Initial", "alice");

        mockMvc.perform(delete("/api/documents/" + doc.getId())
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNotFound());

        assertThat(documentRepository.findById(doc.getId())).isPresent();
    }
}
