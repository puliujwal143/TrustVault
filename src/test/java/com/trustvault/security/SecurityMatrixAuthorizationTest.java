package com.trustvault.security;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Comprehensive Automated Authorization Security Matrix Tests.
 *
 * Verifies all security boundaries defined by the Hackathon specification:
 * - Owner: full access (read, download, upload, edit, delete, share management)
 * - READ collaborator: read metadata and download; NO edit, upload, delete, or share management
 * - EDIT collaborator: read metadata, download, edit, upload; NO delete or share management
 * - Unshared authenticated user: zero access (HTTP 404 anti-IDOR across all document endpoints)
 * - Unauthenticated user: HTTP 401 Unauthorized (REST) or HTTP 302 redirect to /login (Web)
 * - Admin without grant (Zero Trust): HTTP 404 anti-IDOR (cannot access private documents)
 * - Revoked collaborator: immediately blocked with HTTP 404 anti-IDOR
 * - Search isolation across multiple owners: no leakage of unshared documents
 * - Audit history isolation and URL parameter tampering defense
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityMatrixAuthorizationTest {

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

    private User owner;
    private User readCollab;
    private User editCollab;
    private User unsharedUser;
    private User admin;
    private Document testDoc;

    @BeforeEach
    void setUp() {
        if (storageService != null) {
            storageService.deleteAll();
        }
        jdbcTemplate.execute("DELETE FROM audit_events");
        documentShareRepository.deleteAll();
        documentRepository.deleteAll();
        userRepository.deleteAll();

        owner = userService.createUser("matrix_owner", "Password123!", "owner@example.com", Role.ROLE_USER);
        readCollab = userService.createUser("matrix_read", "Password123!", "read@example.com", Role.ROLE_USER);
        editCollab = userService.createUser("matrix_edit", "Password123!", "edit@example.com", Role.ROLE_USER);
        unsharedUser = userService.createUser("matrix_stranger", "Password123!", "stranger@example.com", Role.ROLE_USER);
        admin = userService.createUser("matrix_admin", "Password123!", "admin@example.com", Role.ROLE_ADMIN);

        // Create base test document owned by matrix_owner
        testDoc = documentService.createDocument("Matrix Security Plan", "Confidential architecture doc", owner.getUsername());

        // Attach a valid file payload to testDoc
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "security-plan.pdf",
                "application/pdf",
                "%PDF-1.4 header bytes for matrix testing".getBytes(StandardCharsets.UTF_8)
        );
        documentService.uploadFile(testDoc.getId(), file, owner.getUsername(), "127.0.0.1");

        // Grant READ to readCollab
        documentShareService.grantAccess(testDoc.getId(), readCollab.getUsername(), SharePermission.READ, owner.getUsername());

        // Grant EDIT to editCollab
        documentShareService.grantAccess(testDoc.getId(), editCollab.getUsername(), SharePermission.EDIT, owner.getUsername());
    }

    @AfterEach
    void tearDown() {
        if (storageService != null) {
            storageService.deleteAll();
        }
    }

    // =========================================================================
    // 1. OWNER BOUNDARY
    // =========================================================================
    @Nested
    @DisplayName("1. Owner Access Boundary")
    class OwnerAccessTests {

        @Test
        @DisplayName("Owner can read metadata, download, upload, edit, delete, and manage shares")
        void testOwnerFullAccess() throws Exception {
            // Read metadata
            mockMvc.perform(get("/api/documents/" + testDoc.getId()).with(user(owner.getUsername())))
                    .andExpect(status().isOk());

            // Download file
            mockMvc.perform(get("/api/documents/" + testDoc.getId() + "/download").with(user(owner.getUsername())))
                    .andExpect(status().isOk());

            // Upload / replace file
            MockMultipartFile newFile = new MockMultipartFile(
                    "file", "new-plan.pdf", "application/pdf", "%PDF-1.4 new bytes".getBytes(StandardCharsets.UTF_8)
            );
            mockMvc.perform(multipart("/api/documents/" + testDoc.getId() + "/file")
                            .file(newFile)
                            .with(user(owner.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isOk());

            // Edit metadata
            UpdateDocumentForm editReq = new UpdateDocumentForm("Owner Updated Title", "Owner Updated Desc");
            mockMvc.perform(put("/api/documents/" + testDoc.getId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(editReq))
                            .with(user(owner.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isOk());

            // Grant share
            mockMvc.perform(post("/documents/" + testDoc.getId() + "/shares")
                            .param("granteeUsername", unsharedUser.getUsername())
                            .param("permission", "READ")
                            .with(user(owner.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isFound());

            // Revoke share
            mockMvc.perform(post("/documents/" + testDoc.getId() + "/shares/revoke")
                            .param("granteeUsername", unsharedUser.getUsername())
                            .with(user(owner.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isFound());

            // Delete document
            mockMvc.perform(delete("/api/documents/" + testDoc.getId())
                            .with(user(owner.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isNoContent());
        }
    }

    // =========================================================================
    // 2. READ COLLABORATOR BOUNDARY
    // =========================================================================
    @Nested
    @DisplayName("2. READ Collaborator Boundary")
    class ReadCollaboratorTests {

        @Test
        @DisplayName("READ collaborator CAN read metadata and download file")
        void testReadCollaboratorAllowedActions() throws Exception {
            // Read metadata (web and REST)
            mockMvc.perform(get("/documents/" + testDoc.getId()).with(user(readCollab.getUsername())))
                    .andExpect(status().isOk());
            mockMvc.perform(get("/api/documents/" + testDoc.getId()).with(user(readCollab.getUsername())))
                    .andExpect(status().isOk());

            // Download file
            mockMvc.perform(get("/api/documents/" + testDoc.getId() + "/download").with(user(readCollab.getUsername())))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("READ collaborator CANNOT edit, upload, delete, or manage shares (403 Forbidden)")
        void testReadCollaboratorDeniedActions() throws Exception {
            // Attempt metadata edit (REST) -> 403
            UpdateDocumentForm editReq = new UpdateDocumentForm("Hacked Title", "Hacked Desc");
            mockMvc.perform(put("/api/documents/" + testDoc.getId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(editReq))
                            .with(user(readCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isForbidden());

            // Attempt file upload / replace -> 403
            MockMultipartFile file = new MockMultipartFile(
                    "file", "tamper.pdf", "application/pdf", "%PDF-1.4 payload".getBytes(StandardCharsets.UTF_8)
            );
            mockMvc.perform(multipart("/api/documents/" + testDoc.getId() + "/file")
                            .file(file)
                            .with(user(readCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isForbidden());

            // Attempt deletion -> 403
            mockMvc.perform(delete("/api/documents/" + testDoc.getId())
                            .with(user(readCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isForbidden());

            // Attempt share grant -> 403
            mockMvc.perform(post("/documents/" + testDoc.getId() + "/shares")
                            .param("granteeUsername", unsharedUser.getUsername())
                            .param("permission", "READ")
                            .with(user(readCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isForbidden());
        }
    }

    // =========================================================================
    // 3. EDIT COLLABORATOR BOUNDARY
    // =========================================================================
    @Nested
    @DisplayName("3. EDIT Collaborator Boundary")
    class EditCollaboratorTests {

        @Test
        @DisplayName("EDIT collaborator CAN read metadata, download file, edit metadata, and upload files")
        void testEditCollaboratorAllowedActions() throws Exception {
            // Read metadata
            mockMvc.perform(get("/api/documents/" + testDoc.getId()).with(user(editCollab.getUsername())))
                    .andExpect(status().isOk());

            // Download file
            mockMvc.perform(get("/api/documents/" + testDoc.getId() + "/download").with(user(editCollab.getUsername())))
                    .andExpect(status().isOk());

            // Edit metadata
            UpdateDocumentForm editReq = new UpdateDocumentForm("Collaborator Edited Title", "New Notes");
            mockMvc.perform(put("/api/documents/" + testDoc.getId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(editReq))
                            .with(user(editCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isOk());

            // Upload / replace file
            MockMultipartFile file = new MockMultipartFile(
                    "file", "collab-version.pdf", "application/pdf", "%PDF-1.4 collab version".getBytes(StandardCharsets.UTF_8)
            );
            mockMvc.perform(multipart("/api/documents/" + testDoc.getId() + "/file")
                            .file(file)
                            .with(user(editCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("EDIT collaborator CANNOT delete document or manage shares (403 Forbidden)")
        void testEditCollaboratorDeniedActions() throws Exception {
            // Attempt deletion (REST) -> 403
            mockMvc.perform(delete("/api/documents/" + testDoc.getId())
                            .with(user(editCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isForbidden());

            // Attempt deletion (Web) -> 403
            mockMvc.perform(post("/documents/" + testDoc.getId() + "/delete")
                            .with(user(editCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isForbidden());

            // Attempt share grant -> 403
            mockMvc.perform(post("/documents/" + testDoc.getId() + "/shares")
                            .param("granteeUsername", unsharedUser.getUsername())
                            .param("permission", "READ")
                            .with(user(editCollab.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isForbidden());
        }
    }

    // =========================================================================
    // 4. UNSHARED AUTHENTICATED USER (ANTI-IDOR)
    // =========================================================================
    @Nested
    @DisplayName("4. Unshared Authenticated User (Anti-IDOR)")
    class UnsharedUserTests {

        @Test
        @DisplayName("Unshared user receives 404 Not Found on all operations without revealing existence")
        void testUnsharedUserAntiIdor() throws Exception {
            // View web page -> 404
            mockMvc.perform(get("/documents/" + testDoc.getId()).with(user(unsharedUser.getUsername())))
                    .andExpect(status().isNotFound());

            // Read REST -> 404
            mockMvc.perform(get("/api/documents/" + testDoc.getId()).with(user(unsharedUser.getUsername())))
                    .andExpect(status().isNotFound());

            // Download file -> 404
            mockMvc.perform(get("/api/documents/" + testDoc.getId() + "/download").with(user(unsharedUser.getUsername())))
                    .andExpect(status().isNotFound());

            // Upload file -> 404
            MockMultipartFile file = new MockMultipartFile(
                    "file", "exploit.pdf", "application/pdf", "%PDF-1.4 exploit".getBytes(StandardCharsets.UTF_8)
            );
            mockMvc.perform(multipart("/api/documents/" + testDoc.getId() + "/file")
                            .file(file)
                            .with(user(unsharedUser.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isNotFound());

            // Edit metadata -> 404
            UpdateDocumentForm editReq = new UpdateDocumentForm("Tampered", "Desc");
            mockMvc.perform(put("/api/documents/" + testDoc.getId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(editReq))
                            .with(user(unsharedUser.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isNotFound());

            // Delete document -> 404
            mockMvc.perform(delete("/api/documents/" + testDoc.getId())
                            .with(user(unsharedUser.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isNotFound());

            // Manage shares -> 404
            mockMvc.perform(post("/documents/" + testDoc.getId() + "/shares")
                            .param("granteeUsername", "anyone")
                            .param("permission", "READ")
                            .with(user(unsharedUser.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isNotFound());
        }
    }

    // =========================================================================
    // 5. UNAUTHENTICATED REQUESTS
    // =========================================================================
    @Nested
    @DisplayName("5. Unauthenticated User Boundary")
    class UnauthenticatedUserTests {

        @Test
        @DisplayName("Unauthenticated requests are rejected with 401 Unauthorized or redirected to login")
        void testUnauthenticatedDenials() throws Exception {
            // Web page view -> redirect to login (302)
            mockMvc.perform(get("/documents/" + testDoc.getId()).accept(MediaType.TEXT_HTML))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("http://localhost/login"));

            // REST get -> 401
            mockMvc.perform(get("/api/documents/" + testDoc.getId()))
                    .andExpect(status().isUnauthorized());

            // REST download -> 401
            mockMvc.perform(get("/api/documents/" + testDoc.getId() + "/download"))
                    .andExpect(status().isUnauthorized());

            // REST edit -> 401
            UpdateDocumentForm editReq = new UpdateDocumentForm("Tampered", "Desc");
            mockMvc.perform(put("/api/documents/" + testDoc.getId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(editReq))
                            .with(csrf()))
                    .andExpect(status().isUnauthorized());

            // REST delete -> 401
            mockMvc.perform(delete("/api/documents/" + testDoc.getId()).with(csrf()))
                    .andExpect(status().isUnauthorized());
        }
    }

    // =========================================================================
    // 6. ADMIN ZERO-TRUST (NO AUTOMATIC BYPASS OF PRIVATE DOCUMENTS)
    // =========================================================================
    @Nested
    @DisplayName("6. Admin Zero-Trust Boundary")
    class AdminZeroTrustTests {

        @Test
        @DisplayName("Admin without an explicit share grant CANNOT access private document (receives 404 anti-IDOR)")
        void testAdminZeroTrustEnforcement() throws Exception {
            // Web view -> 404
            mockMvc.perform(get("/documents/" + testDoc.getId()).with(user(admin.getUsername())))
                    .andExpect(status().isNotFound());

            // REST read -> 404
            mockMvc.perform(get("/api/documents/" + testDoc.getId()).with(user(admin.getUsername())))
                    .andExpect(status().isNotFound());

            // Download -> 404
            mockMvc.perform(get("/api/documents/" + testDoc.getId() + "/download").with(user(admin.getUsername())))
                    .andExpect(status().isNotFound());

            // Edit -> 404
            UpdateDocumentForm editReq = new UpdateDocumentForm("Admin Edit", "Desc");
            mockMvc.perform(put("/api/documents/" + testDoc.getId())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(editReq))
                            .with(user(admin.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isNotFound());

            // Delete -> 404
            mockMvc.perform(delete("/api/documents/" + testDoc.getId())
                            .with(user(admin.getUsername()))
                            .with(csrf()))
                    .andExpect(status().isNotFound());
        }
    }

    // =========================================================================
    // 7. REVOKED COLLABORATOR BOUNDARY
    // =========================================================================
    @Nested
    @DisplayName("7. Revoked Collaborator Boundary")
    class RevokedCollaboratorTests {

        @Test
        @DisplayName("Revoked collaborator is immediately blocked with 404 Not Found")
        void testRevokedCollaboratorImmediateDenial() throws Exception {
            // Revoke readCollab's access
            documentShareService.revokeAccess(testDoc.getId(), readCollab.getUsername(), owner.getUsername());

            // Re-attempt read -> 404
            mockMvc.perform(get("/documents/" + testDoc.getId()).with(user(readCollab.getUsername())))
                    .andExpect(status().isNotFound());

            mockMvc.perform(get("/api/documents/" + testDoc.getId()).with(user(readCollab.getUsername())))
                    .andExpect(status().isNotFound());

            // Re-attempt download -> 404
            mockMvc.perform(get("/api/documents/" + testDoc.getId() + "/download").with(user(readCollab.getUsername())))
                    .andExpect(status().isNotFound());
        }
    }

    // =========================================================================
    // 8. SEARCH & FILTERING CROSS-OWNER ISOLATION
    // =========================================================================
    @Nested
    @DisplayName("8. Search Cross-Owner Isolation")
    class SearchIsolationTests {

        @Test
        @DisplayName("Search queries never leak unshared documents across different owners")
        void testSearchIsolation() throws Exception {
            // unsharedUser creates a private document with distinct keywords
            documentService.createDocument("Secret Financial Roadmap", "Classified data", unsharedUser.getUsername());

            // Owner searches for "Roadmap" -> must NOT return unsharedUser's document
            mockMvc.perform(get("/documents").param("q", "Roadmap").with(user(owner.getUsername())))
                    .andExpect(status().isOk())
                    .andExpect(content().string(not(containsString("Secret Financial Roadmap"))));

            // Owner filters by owner=matrix_stranger -> returns empty list
            mockMvc.perform(get("/documents").param("owner", unsharedUser.getUsername()).with(user(owner.getUsername())))
                    .andExpect(status().isOk())
                    .andExpect(content().string(not(containsString("Secret Financial Roadmap"))))
                    .andExpect(content().string(containsString("No documents found")));
        }

        @Test
        @DisplayName("Category filtering never leaks unshared documents across different owners")
        void testCategorySearchIsolation() throws Exception {
            // unsharedUser creates a private document with a distinctive category
            documentService.createDocument("Secret Financial Roadmap", "Classified data", "HighlyClassified", unsharedUser.getUsername());

            // Owner searches for category "HighlyClassified" via Web -> must NOT return unsharedUser's document
            mockMvc.perform(get("/documents").param("category", "HighlyClassified").with(user(owner.getUsername())))
                    .andExpect(status().isOk())
                    .andExpect(content().string(not(containsString("Secret Financial Roadmap"))))
                    .andExpect(content().string(containsString("No documents found")));

            // Owner searches for category "HighlyClassified" via REST -> returns empty JSON array
            mockMvc.perform(get("/api/documents").param("category", "HighlyClassified").with(user(owner.getUsername())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$", hasSize(0)));
        }
    }

    // =========================================================================
    // 9. AUDIT HISTORY & URL TAMPERING
    // =========================================================================
    @Nested
    @DisplayName("9. Audit History Isolation & URL Tampering")
    class AuditTamperingTests {

        @Test
        @DisplayName("Non-admin user tampering with ?actor= query parameter is rejected with 403 Forbidden")
        void testAuditQueryTamperingRejected() throws Exception {
            mockMvc.perform(get("/audit").param("actor", owner.getUsername()).with(user(readCollab.getUsername())))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Non-admin user sees only their own audit events")
        void testAuditHistoryScopedToSelf() throws Exception {
            mockMvc.perform(get("/audit").with(user(owner.getUsername())))
                    .andExpect(status().isOk())
                    .andExpect(content().string(not(containsString(unsharedUser.getUsername()))));
        }
    }
}
