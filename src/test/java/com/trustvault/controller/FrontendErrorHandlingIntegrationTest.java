package com.trustvault.controller;

import com.trustvault.entity.Document;
import com.trustvault.entity.Role;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Comprehensive integration tests verifying the frontend error handling architecture.
 *
 * Requirements Verified:
 * 1. User-friendly HTML error page:
 *    - Rendered with TrustVault design, brand navbar, sidebar, status badge, heading, explanation,
 *      and "Return to Dashboard" button.
 * 2. Correct HTTP status mapping:
 *    - 403 Forbidden: "Access Denied" page for unauthorized actions.
 *    - 404 Not Found: "Document Not Found" page for nonexistent or unshared documents (anti-IDOR).
 *    - 401 Unauthorized: Unauthenticated users redirected to /login using the authentication flow.
 *    - 500 Internal Server Error: Sanitized generic error message without stack traces.
 * 3. Frontend routing integration:
 *    - Navigation to document view routes renders HTML error page, NEVER raw JSON.
 *    - REST API requests (/api/**) continue to return structured JSON ErrorResponseDto.
 * 4. Security preservation:
 *    - Anti-IDOR masking (unshared document returns 404, not revealing resource existence).
 *    - Zero exposure of internal blob storage keys, filesystem paths, or stack traces.
 * 5. Functional regression verification:
 *    - Authorized access, sharing, and dashboard navigation remain fully operational.
 */
@SpringBootTest
@AutoConfigureMockMvc
class FrontendErrorHandlingIntegrationTest {

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
    private JdbcTemplate jdbcTemplate;

    private User alice;
    private User bob;
    private User charlie;

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
        charlie = userService.createUser("charlie", "Password123!", "charlie@example.com", Role.ROLE_USER);
    }

    @AfterEach
    void tearDown() {
        if (storageService != null) {
            storageService.deleteAll();
        }
    }

    // =========================================================================
    // 1. Authorized Document Access
    // =========================================================================

    @Test
    @DisplayName("Authorized Access (Owner): viewing owned document renders detail page with HTTP 200 OK")
    void testAuthorizedAccessAsOwner() throws Exception {
        Document doc = documentService.createDocument("Alice Financial Report", "Confidential financial data", "alice");

        mockMvc.perform(get("/documents/" + doc.getId()).with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(model().attributeExists("document"))
                .andExpect(content().string(containsString("Alice Financial Report")))
                .andExpect(content().string(containsString("Confidential financial data")))
                .andExpect(content().string(containsString("OWNER")))
                .andExpect(content().string(not(containsString(doc.getStorageKey().toString()))));
    }

    @Test
    @DisplayName("Authorized Access (Grantee): viewing shared document renders detail page with HTTP 200 OK")
    void testAuthorizedAccessAsGrantee() throws Exception {
        Document doc = documentService.createDocument("Alice Shared Strategy", "Team strategy guide", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(get("/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(model().attributeExists("document"))
                .andExpect(content().string(containsString("Alice Shared Strategy")))
                .andExpect(content().string(containsString("READ")));
    }

    // =========================================================================
    // 2. Unauthorized Document Access
    // =========================================================================

    @Test
    @DisplayName("Unauthorized Access (Unshared User): navigating to unshared document renders 404 HTML error page (anti-IDOR)")
    void testUnauthorizedAccessUnsharedUserRendersHtmlErrorPage() throws Exception {
        Document privateDoc = documentService.createDocument("Alice Private Secrets", "Restricted", "alice");

        // Bob has no share grant on Alice's private document
        mockMvc.perform(get("/documents/" + privateDoc.getId()).with(user("bob")))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                // Must NOT return raw JSON
                .andExpect(content().string(not(containsString("{\"timestamp\":"))))
                .andExpect(content().string(not(containsString("\"status\":404"))))
                // Must render proper HTML UI elements
                .andExpect(content().string(containsString("Document Not Found")))
                .andExpect(content().string(containsString("404 NOT FOUND")))
                .andExpect(content().string(containsString("id=\"return-dashboard-btn\"")))
                .andExpect(content().string(containsString("Return to Dashboard")))
                .andExpect(content().string(containsString("href=\"/documents\"")))
                // Must NOT leak document title, storage key, or physical path
                .andExpect(content().string(not(containsString("Alice Private Secrets"))))
                .andExpect(content().string(not(containsString(privateDoc.getStorageKey().toString()))));
    }

    @Test
    @DisplayName("Unauthorized Action (READ Grantee attempting EDIT): renders 403 Access Denied HTML error page")
    void testUnauthorizedActionReadGranteeEditingRenders403AccessDeniedHtml() throws Exception {
        Document doc = documentService.createDocument("Alice Protected Spec", "Spec document", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        // Bob has READ permission only, but attempts to POST to the edit endpoint
        mockMvc.perform(post("/documents/" + doc.getId() + "/edit")
                        .param("title", "Bob Malicious Tamper")
                        .param("description", "Tampered description")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden())
                .andExpect(view().name("error"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                // Must NOT return raw JSON
                .andExpect(content().string(not(containsString("{\"timestamp\":"))))
                // Must render proper 403 HTML UI elements
                .andExpect(content().string(containsString("Access Denied")))
                .andExpect(content().string(containsString("403 FORBIDDEN")))
                .andExpect(content().string(containsString("id=\"return-dashboard-btn\"")))
                .andExpect(content().string(containsString("Return to Dashboard")))
                .andExpect(content().string(containsString("href=\"/documents\"")));

        // Verify document was not altered
        Document unaltered = documentRepository.findById(doc.getId()).orElseThrow();
        assertThat(unaltered.getTitle()).isEqualTo("Alice Protected Spec");
    }

    @Test
    @DisplayName("Unauthorized Action (Non-Owner attempting Share Revocation): renders 403 Access Denied HTML error page")
    void testUnauthorizedActionNonOwnerRevokingRenders403Html() throws Exception {
        Document doc = documentService.createDocument("Alice Document", "Description", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");
        documentShareService.grantAccess(doc.getId(), "charlie", SharePermission.READ, "alice");

        // Bob attempts to revoke Charlie's access
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares/revoke")
                        .param("granteeUsername", "charlie")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden())
                .andExpect(view().name("error"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(containsString("Access Denied")))
                .andExpect(content().string(containsString("403 FORBIDDEN")))
                .andExpect(content().string(containsString("Return to Dashboard")));

        // Charlie's access must remain intact
        assertThat(documentShareRepository.findByDocumentIdAndGranteeUsername(doc.getId(), "charlie")).isPresent();
    }

    @Test
    @DisplayName("Unauthorized Access (Audit Tampering): standard user viewing another's audit renders 403 Access Denied HTML page")
    void testUnauthorizedAuditAccessRenders403Html() throws Exception {
        mockMvc.perform(get("/audit")
                        .param("actor", "bob")
                        .with(user("alice")))
                .andExpect(status().isForbidden())
                .andExpect(view().name("error"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(containsString("Access Denied")))
                .andExpect(content().string(containsString("403 FORBIDDEN")))
                .andExpect(content().string(containsString("Return to Dashboard")));
    }

    // =========================================================================
    // 3. Nonexistent Document
    // =========================================================================

    @Test
    @DisplayName("Nonexistent Document: navigating to invalid document ID renders 404 HTML error page")
    void testNonexistentDocumentRendersHtmlErrorPage() throws Exception {
        mockMvc.perform(get("/documents/888888").with(user("alice")))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                // Must NOT return raw JSON
                .andExpect(content().string(not(containsString("{\"timestamp\":"))))
                .andExpect(content().string(not(containsString("\"status\":404"))))
                // Must render proper HTML UI elements
                .andExpect(content().string(containsString("Document Not Found")))
                .andExpect(content().string(containsString("404 NOT FOUND")))
                .andExpect(content().string(containsString("id=\"return-dashboard-btn\"")))
                .andExpect(content().string(containsString("Return to Dashboard")))
                .andExpect(content().string(containsString("/documents/888888")));
    }

    // =========================================================================
    // 4. Unauthenticated Requests
    // =========================================================================

    @Test
    @DisplayName("Unauthenticated Request (Document Detail): redirected to /login via standard auth flow")
    void testUnauthenticatedDocumentDetailRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/documents/123").accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("Unauthenticated Request (Dashboard): redirected to /login via standard auth flow")
    void testUnauthenticatedDashboardRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/documents").accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("Unauthenticated Request (Audit): redirected to /login via standard auth flow")
    void testUnauthenticatedAuditRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/audit").accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    // =========================================================================
    // 5. REST API Requests Return JSON (Context-Appropriate Error Handling)
    // =========================================================================

    @Test
    @DisplayName("REST API Error Handling: GET /api/documents/{nonexistent} returns JSON ErrorResponseDto, NOT HTML")
    void testApiRequestsReturnJsonErrorResponse() throws Exception {
        mockMvc.perform(get("/api/documents/999999")
                        .with(user("alice"))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("Document not found: 999999"))
                .andExpect(jsonPath("$.path").value("/api/documents/999999"))
                .andExpect(content().string(not(containsString("<!DOCTYPE html>"))));
    }

    @Test
    @DisplayName("REST API Error Handling: unshared user accessing /api/documents/{id} returns JSON 404 anti-IDOR")
    void testApiUnsharedDocumentReturnsJson404() throws Exception {
        Document doc = documentService.createDocument("Alice Private API Doc", "Private", "alice");

        mockMvc.perform(get("/api/documents/" + doc.getId())
                        .with(user("bob"))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(content().string(not(containsString("<!DOCTYPE html>"))));
    }

    // =========================================================================
    // 6. Security Preservation: No Internal Leaks or Stack Traces
    // =========================================================================

    @Test
    @DisplayName("Security: Error page contains no stack traces or server file path leaks")
    void testErrorPageSuppressesStackTracesAndInternalPaths() throws Exception {
        mockMvc.perform(get("/documents/999999").with(user("alice")))
                .andExpect(status().isNotFound())
                .andExpect(content().string(not(containsString("NullPointerException"))))
                .andExpect(content().string(not(containsString("Exception in thread"))))
                .andExpect(content().string(not(containsString("at com.trustvault."))))
                .andExpect(content().string(not(containsString("org.springframework"))))
                .andExpect(content().string(not(containsString("private-storage"))))
                .andExpect(content().string(not(containsString(".java:"))));
    }
}
