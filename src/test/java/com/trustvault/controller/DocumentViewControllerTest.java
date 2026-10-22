package com.trustvault.controller;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
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
import com.trustvault.dto.DocumentDetailViewModel;
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
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Integration tests for DocumentViewController:
 * - Root redirect (GET / -> /documents)
 * - Dashboard document listing (GET /documents)
 * - Empty state rendering
 * - Accurate owned/shared badges and permission indicators
 * - Filter tabs (all, owned, shared)
 * - Document creation form handling (POST /documents) with PRG pattern
 * - Bean validation bounds (title 1-255, description max 1000)
 * - CSRF enforcement and access isolation
 */
@SpringBootTest
@AutoConfigureMockMvc
class DocumentViewControllerTest {

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
    @DisplayName("GET /: unauthenticated request is redirected to /login")
    void testRootUnauthenticatedRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/").accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("GET /: authenticated user is redirected to /documents")
    void testRootAuthenticatedRedirectsToDocuments() throws Exception {
        mockMvc.perform(get("/").with(user("alice")))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents"));
    }

    @Test
    @DisplayName("GET /documents: unauthenticated request is redirected to /login")
    void testDocumentsUnauthenticatedRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/documents").accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("GET /documents: displays empty state when user has no accessible documents")
    void testEmptyStateWhenNoDocuments() throws Exception {
        mockMvc.perform(get("/documents").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().attribute("totalCount", 0L))
                .andExpect(model().attribute("ownedCount", 0L))
                .andExpect(model().attribute("sharedCount", 0L))
                .andExpect(content().string(containsString("No documents found")))
                .andExpect(content().string(containsString("Create First Document")));
    }

    @Test
    @DisplayName("GET /documents: lists owned and shared documents with correct permission badges and metrics")
    void testListOwnedAndSharedDocuments() throws Exception {
        // Alice creates 1 document
        Document aliceDoc = documentService.createDocument("Alice Strategy Plan", "Q4 Strategy Plan", "alice");

        // Bob creates 2 documents
        Document bobSharedRead = documentService.createDocument("Bob Guidelines", "Security guidelines", "bob");
        Document bobSharedEdit = documentService.createDocument("Bob Architecture", "Core architecture", "bob");
        Document bobPrivate = documentService.createDocument("Bob Secret Finances", "Private finances", "bob");

        // Bob shares 1 with READ and 1 with EDIT to Alice
        documentShareService.grantAccess(bobSharedRead.getId(), "alice", SharePermission.READ, "bob");
        documentShareService.grantAccess(bobSharedEdit.getId(), "alice", SharePermission.EDIT, "bob");

        mockMvc.perform(get("/documents").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().attribute("totalCount", 3L))
                .andExpect(model().attribute("ownedCount", 1L))
                .andExpect(model().attribute("sharedCount", 2L))
                // Alice's document should appear with OWNER badge
                .andExpect(content().string(containsString("Alice Strategy Plan")))
                .andExpect(content().string(containsString("OWNER")))
                // Bob's shared documents should appear with READ and EDIT badges
                .andExpect(content().string(containsString("Bob Guidelines")))
                .andExpect(content().string(containsString("READ")))
                .andExpect(content().string(containsString("Bob Architecture")))
                .andExpect(content().string(containsString("EDIT")))
                // Bob's unshared document must strictly NOT appear (anti-IDOR)
                .andExpect(content().string(not(containsString("Bob Secret Finances"))));
    }

    @Test
    @DisplayName("GET /documents?filter=owned: filters to only owned documents")
    void testFilterOwnedDocuments() throws Exception {
        documentService.createDocument("Alice Doc 1", "Desc 1", "alice");
        Document bobDoc = documentService.createDocument("Bob Shared Doc", "Shared", "bob");
        documentShareService.grantAccess(bobDoc.getId(), "alice", SharePermission.READ, "bob");

        mockMvc.perform(get("/documents").param("filter", "owned").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().attribute("activeFilter", "owned"))
                .andExpect(content().string(containsString("Alice Doc 1")))
                .andExpect(content().string(not(containsString("Bob Shared Doc"))));
    }

    @Test
    @DisplayName("GET /documents?filter=shared: filters to only shared documents")
    void testFilterSharedDocuments() throws Exception {
        documentService.createDocument("Alice Doc 1", "Desc 1", "alice");
        Document bobDoc = documentService.createDocument("Bob Shared Doc", "Shared", "bob");
        documentShareService.grantAccess(bobDoc.getId(), "alice", SharePermission.READ, "bob");

        mockMvc.perform(get("/documents").param("filter", "shared").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().attribute("activeFilter", "shared"))
                .andExpect(content().string(not(containsString("Alice Doc 1"))))
                .andExpect(content().string(containsString("Bob Shared Doc")));
    }

    @Test
    @DisplayName("POST /documents: valid input creates document, records audit, and redirects with PRG flash message")
    void testCreateDocumentSuccess() throws Exception {
        mockMvc.perform(post("/documents")
                .param("title", "Project Alpha Plan")
                .param("description", "High-security roadmap for Project Alpha")
                .with(user("alice"))
                .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents"))
                .andExpect(flash().attribute("successMessage", containsString("Project Alpha Plan")));

        // Verify entity persisted in database with correct owner
        List<Document> docs = documentRepository.findAllAccessibleByUsername("alice");
        assertThat(docs).hasSize(1);
        assertThat(docs.get(0).getTitle()).isEqualTo("Project Alpha Plan");
        assertThat(docs.get(0).getDescription()).isEqualTo("High-security roadmap for Project Alpha");
        assertThat(docs.get(0).getOwner().getUsername()).isEqualTo("alice");

        // Verify audit event recorded
        List<AuditEvent> events = auditEventRepository.findByActorUsernameOrderByTimestampDesc("alice");
        assertThat(events).anyMatch(e -> e.getAction() == AuditAction.DOCUMENT_CREATE);
    }

    @Test
    @DisplayName("POST /documents: blank title fails validation and re-displays form with error without redirecting")
    void testCreateDocumentBlankTitleFailsValidation() throws Exception {
        mockMvc.perform(post("/documents")
                .param("title", "   ")
                .param("description", "Some description")
                .with(user("alice"))
                .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().hasErrors())
                .andExpect(model().attributeHasFieldErrors("createDocumentForm", "title"))
                .andExpect(content().string(containsString("Document title is required")));

        // No document created
        assertThat(documentRepository.count()).isEqualTo(0);
    }

    @Test
    @DisplayName("POST /documents: title exceeding 255 characters fails validation")
    void testCreateDocumentTitleTooLongFailsValidation() throws Exception {
        String longTitle = "A".repeat(256);

        mockMvc.perform(post("/documents")
                .param("title", longTitle)
                .param("description", "Valid description")
                .with(user("alice"))
                .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().hasErrors())
                .andExpect(model().attributeHasFieldErrors("createDocumentForm", "title"))
                .andExpect(content().string(containsString("must not exceed 255 characters")));

        assertThat(documentRepository.count()).isEqualTo(0);
    }

    @Test
    @DisplayName("POST /documents: description exceeding 1000 characters fails validation and preserves entered title")
    void testCreateDocumentDescriptionTooLongFailsValidation() throws Exception {
        String longDesc = "D".repeat(1001);

        mockMvc.perform(post("/documents")
                .param("title", "Valid Document Title")
                .param("description", longDesc)
                .with(user("alice"))
                .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().hasErrors())
                .andExpect(model().attributeHasFieldErrors("createDocumentForm", "description"))
                .andExpect(content().string(containsString("must not exceed 1000 characters")))
                // Verify user's valid title is preserved in input field
                .andExpect(content().string(containsString("Valid Document Title")));

        assertThat(documentRepository.count()).isEqualTo(0);
    }

    @Test
    @DisplayName("POST /documents: request without CSRF token is rejected with HTTP 403 Forbidden")
    void testCreateDocumentWithoutCsrfRejected() throws Exception {
        mockMvc.perform(post("/documents")
                .param("title", "Forbidden Doc")
                .with(user("alice")))
                .andExpect(status().isForbidden());

        assertThat(documentRepository.count()).isEqualTo(0);
    }

    @Test
    @DisplayName("ROLE_ADMIN without explicit share grant does NOT see Alice's private documents")
    void testAdminCannotBypassDocumentAuthorizationOnDashboard() throws Exception {
        documentService.createDocument("Alice Top Secret", "Classified", "alice");

        mockMvc.perform(get("/documents").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(model().attribute("totalCount", 0L))
                .andExpect(content().string(not(containsString("Alice Top Secret"))));
    }

    // =========================================================================
    // Document Detail View (GET /documents/{id}) & Link Navigation Tests
    // =========================================================================

    @Test
    @DisplayName("GET /documents: titles render accessible styled links to /documents/{id}")
    void testDashboardRendersDocumentLinks() throws Exception {
        Document aliceDoc = documentService.createDocument("Alice Roadmap 2026", "Strategic Roadmap", "alice");

        mockMvc.perform(get("/documents").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/list"))
                .andExpect(content().string(containsString("href=\"/documents/" + aliceDoc.getId() + "\"")))
                .andExpect(content().string(containsString("class=\"doc-title-link\"")));
    }

    @Test
    @DisplayName("GET /documents/{id}: unauthenticated request is redirected to /login")
    void testGetDocumentDetailUnauthenticatedRedirectsToLogin() throws Exception {
        Document aliceDoc = documentService.createDocument("Alice Sensitive Doc", "Sensitive", "alice");

        mockMvc.perform(get("/documents/" + aliceDoc.getId()).accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("GET /documents/{id}: owner can view document details, OWNER badge, and shared collaborators list")
    void testGetDocumentDetailAsOwnerSuccess() throws Exception {
        Document aliceDoc = documentService.createDocument("Alice Financial Review", "Confidential review", "alice");
        documentShareService.grantAccess(aliceDoc.getId(), "bob", SharePermission.READ, "alice");

        MvcResult result = mockMvc.perform(get("/documents/" + aliceDoc.getId()).with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(model().attributeExists("document"))
                .andExpect(content().string(containsString("Alice Financial Review")))
                .andExpect(content().string(containsString("Confidential review")))
                .andExpect(content().string(containsString("OWNER")))
                .andExpect(content().string(containsString("Shared Collaborators")))
                .andExpect(content().string(containsString("bob")))
                .andExpect(content().string(not(containsString(aliceDoc.getStorageKey().toString()))))
                .andReturn();

        DocumentDetailViewModel viewModel = (DocumentDetailViewModel) result.getModelAndView().getModel().get("document");
        assertThat(viewModel.id()).isEqualTo(aliceDoc.getId());
        assertThat(viewModel.title()).isEqualTo("Alice Financial Review");
        assertThat(viewModel.ownerUsername()).isEqualTo("alice");
        assertThat(viewModel.isOwner()).isTrue();
        assertThat(viewModel.permissionLabel()).isEqualTo("OWNER");
        assertThat(viewModel.shares()).hasSize(1);
        assertThat(viewModel.shares().get(0).granteeUsername()).isEqualTo("bob");
        assertThat(viewModel.shares().get(0).permission()).isEqualTo("READ");
    }

    @Test
    @DisplayName("GET /documents/{id}: owner views newly created document without shares and without description, records DOCUMENT_READ")
    void testGetDocumentDetailNewlyCreatedWithoutSharesOrDescription() throws Exception {
        Document doc = documentService.createDocument("Test No Shares", null, "alice");
        jdbcTemplate.execute("DELETE FROM audit_events");

        mockMvc.perform(get("/documents/" + doc.getId()).with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(content().string(containsString("Test No Shares")));

        // Verify DOCUMENT_READ audit event is successfully persisted
        List<AuditEvent> readEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.DOCUMENT_READ);
        assertThat(readEvents).hasSize(1);
        assertThat(readEvents.get(0).getActorUsername()).isEqualTo("alice");
        assertThat(readEvents.get(0).getDocumentId()).isEqualTo(doc.getId());
        assertThat(readEvents.get(0).getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
    }

    @Test
    @DisplayName("GET /documents/{id}: READ grantee can view document details with READ badge and share list is hidden")
    void testGetDocumentDetailAsReadGranteeSuccess() throws Exception {
        Document aliceDoc = documentService.createDocument("Alice Shared Guidelines", "Security Guidelines", "alice");
        documentShareService.grantAccess(aliceDoc.getId(), "bob", SharePermission.READ, "alice");

        MvcResult result = mockMvc.perform(get("/documents/" + aliceDoc.getId()).with(user("bob")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(model().attributeExists("document"))
                .andExpect(content().string(containsString("Alice Shared Guidelines")))
                .andExpect(content().string(containsString("READ")))
                .andExpect(content().string(not(containsString("Shared Collaborators"))))
                .andExpect(content().string(not(containsString(aliceDoc.getStorageKey().toString()))))
                .andReturn();

        DocumentDetailViewModel viewModel = (DocumentDetailViewModel) result.getModelAndView().getModel().get("document");
        assertThat(viewModel.isOwner()).isFalse();
        assertThat(viewModel.permissionLabel()).isEqualTo("READ");
        assertThat(viewModel.shares()).isEmpty();
    }

    @Test
    @DisplayName("GET /documents/{id}: unshared user receives 404 Not Found (anti-IDOR)")
    void testGetDocumentDetailAsUnsharedUserReturns404() throws Exception {
        Document aliceDoc = documentService.createDocument("Alice Secret Vault", "Classified", "alice");

        // Bob has no share grant on aliceDoc
        mockMvc.perform(get("/documents/" + aliceDoc.getId()).with(user("bob")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /documents/{id}: non-existent document ID receives 404 Not Found")
    void testGetDocumentDetailNonExistentReturns404() throws Exception {
        mockMvc.perform(get("/documents/999999").with(user("alice")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /documents/{id}: ROLE_ADMIN without explicit grant receives 404 Not Found (anti-IDOR)")
    void testAdminCannotBypassDocumentAuthorizationOnDetailView() throws Exception {
        Document aliceDoc = documentService.createDocument("Alice Ultra Secret", "Classified", "alice");

        mockMvc.perform(get("/documents/" + aliceDoc.getId()).with(user("admin").roles("ADMIN")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /documents/{id}: owner views upload form with CSRF token and supported file extensions")
    void testOwnerViewsDocumentDetail_uploadFormIsRenderedWithCsrfAndSupportedTypes() throws Exception {
        Document doc = documentService.createDocument("Alice Upload Test", "Description", "alice");

        MvcResult result = mockMvc.perform(get("/documents/" + doc.getId()).with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(model().attributeExists("document"))
                .andExpect(content().string(containsString("id=\"file-upload-form\"")))
                .andExpect(content().string(containsString("action=\"/api/documents/" + doc.getId() + "/file\"")))
                .andExpect(content().string(containsString("name=\"file\"")))
                .andExpect(content().string(containsString("accept=\".pdf,.docx,.xlsx,.pptx,.txt,.csv,.png,.jpg,.jpeg\"")))
                .andExpect(content().string(containsString("id=\"upload-file-btn\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(containsString("Attach File Payload")))
                .andReturn();

        DocumentDetailViewModel viewModel = (DocumentDetailViewModel) result.getModelAndView().getModel().get("document");
        assertThat(viewModel.isOwner()).isTrue();
        assertThat(viewModel.canEdit()).isTrue();
        assertThat(viewModel.hasFile()).isFalse();
    }

    @Test
    @DisplayName("GET /documents/{id}: collaborator with EDIT permission sees upload form")
    void testEditCollaboratorViewsDocumentDetail_uploadFormIsRendered() throws Exception {
        Document doc = documentService.createDocument("Alice Edit Collab", "Editable by Bob", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        MvcResult result = mockMvc.perform(get("/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(content().string(containsString("id=\"file-upload-form\"")))
                .andExpect(content().string(containsString("id=\"upload-file-btn\"")))
                .andExpect(content().string(not(containsString("id=\"upload-read-only-notice\""))))
                .andReturn();

        DocumentDetailViewModel viewModel = (DocumentDetailViewModel) result.getModelAndView().getModel().get("document");
        assertThat(viewModel.isOwner()).isFalse();
        assertThat(viewModel.canEdit()).isTrue();
        assertThat(viewModel.permissionLabel()).isEqualTo("EDIT");
    }

    @Test
    @DisplayName("GET /documents/{id}: collaborator with READ permission does NOT see upload form")
    void testReadCollaboratorViewsDocumentDetail_uploadFormIsHidden() throws Exception {
        Document doc = documentService.createDocument("Alice Read Collab", "Read only by Bob", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        MvcResult result = mockMvc.perform(get("/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(content().string(not(containsString("id=\"file-upload-form\""))))
                .andExpect(content().string(not(containsString("id=\"upload-file-btn\""))))
                .andExpect(content().string(containsString("id=\"upload-read-only-notice\"")))
                .andExpect(content().string(containsString("File upload is restricted to the document owner and collaborators with EDIT access.")))
                .andReturn();

        DocumentDetailViewModel viewModel = (DocumentDetailViewModel) result.getModelAndView().getModel().get("document");
        assertThat(viewModel.isOwner()).isFalse();
        assertThat(viewModel.canEdit()).isFalse();
        assertThat(viewModel.permissionLabel()).isEqualTo("READ");
    }

    @Test
    @DisplayName("GET /documents/{id}: document with attached file renders safe metadata and replace button")
    void testDocumentWithAttachedFile_rendersMetadataAndReplaceButton() throws Exception {
        Document doc = documentService.createDocument("Alice With File", "Document with attachment", "alice");
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "quarterly-report.pdf",
                "application/pdf",
                "%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF".getBytes(StandardCharsets.US_ASCII)
        );
        documentService.uploadFile(doc.getId(), file, "alice", "127.0.0.1");

        mockMvc.perform(get("/documents/" + doc.getId()).with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(content().string(containsString("quarterly-report.pdf")))
                .andExpect(content().string(containsString("application/pdf")))
                .andExpect(content().string(containsString("Replace Attached File")))
                .andExpect(content().string(containsString("Replace File")))
                .andExpect(content().string(not(containsString(doc.getStorageKey().toString()))));
    }

    @Test
    @DisplayName("GET /documents/{id}?uploadSuccess=...: displays success message alert")
    void testDocumentDetailUploadSuccessFeedback() throws Exception {
        Document doc = documentService.createDocument("Alice Feedback Doc", "Desc", "alice");

        mockMvc.perform(get("/documents/" + doc.getId())
                        .param("uploadSuccess", "annual_budget.xlsx")
                        .with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(model().attribute("successMessage", "File 'annual_budget.xlsx' was successfully attached."))
                .andExpect(content().string(containsString("id=\"detail-success-alert\"")))
                .andExpect(content().string(containsString("annual_budget.xlsx")))
                .andExpect(content().string(containsString("was successfully attached")));
    }

    @Test
    @DisplayName("GET /documents/{id}?uploadError=...: displays error message alert")
    void testDocumentDetailUploadErrorFeedback() throws Exception {
        Document doc = documentService.createDocument("Alice Error Doc", "Desc", "alice");

        mockMvc.perform(get("/documents/" + doc.getId())
                        .param("uploadError", "Upload payload exceeds the maximum permitted size limit of 10 MiB.")
                        .with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(model().attribute("errorMessage", "Upload payload exceeds the maximum permitted size limit of 10 MiB."))
                .andExpect(content().string(containsString("id=\"detail-server-error-alert\"")))
                .andExpect(content().string(containsString("Upload payload exceeds the maximum permitted size limit of 10 MiB.")));
    }

    @Test
    @DisplayName("POST /api/documents/{id}/file: enforces CSRF protection on upload endpoint")
    void testUploadEndpointFormSubmissionCsrfEnforcement() throws Exception {
        Document doc = documentService.createDocument("Alice Form Post Doc", "Desc", "alice");
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "test.pdf",
                "application/pdf",
                "%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF".getBytes(StandardCharsets.US_ASCII)
        );

        // Submitting to the upload form action URL without CSRF token is rejected with 403 Forbidden
        mockMvc.perform(multipart("/api/documents/" + doc.getId() + "/file")
                        .file(file)
                        .with(user("alice")))
                .andExpect(status().isForbidden());

        // Submitting to the upload form action URL with CSRF token succeeds with 200 OK
        mockMvc.perform(multipart("/api/documents/" + doc.getId() + "/file")
                        .file(file)
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isOk());
    }

    // =========================================================================
    // Document Sharing & Revocation UI / MVC Handler Tests
    // =========================================================================

    @Test
    @DisplayName("GET /documents/{id}: owner views share document form and controls")
    void testOwnerViewsDocumentDetail_shareFormIsRendered() throws Exception {
        Document doc = documentService.createDocument("Alice Share View Test", "Description", "alice");

        mockMvc.perform(get("/documents/" + doc.getId()).with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(content().string(containsString("id=\"share-document-form\"")))
                .andExpect(content().string(containsString("action=\"/documents/" + doc.getId() + "/shares\"")))
                .andExpect(content().string(containsString("id=\"share-username-input\"")))
                .andExpect(content().string(containsString("id=\"share-permission-select\"")))
                .andExpect(content().string(containsString("id=\"share-document-btn\"")))
                .andExpect(content().string(containsString("Share Document")));
    }

    @Test
    @DisplayName("GET /documents/{id}: non-owner does NOT view share document form")
    void testNonOwnerViewsDocumentDetail_shareFormIsHidden() throws Exception {
        Document doc = documentService.createDocument("Alice Non-Owner Share View Test", "Description", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(get("/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isOk())
                .andExpect(view().name("documents/detail"))
                .andExpect(content().string(not(containsString("id=\"share-document-form\""))))
                .andExpect(content().string(not(containsString("id=\"share-document-btn\""))));
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: owner grants READ permission successfully (PRG & Audit)")
    void testOwnerSharesDocumentWithReadPermissionSuccess() throws Exception {
        Document doc = documentService.createDocument("Alice Share Read Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "READ")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("successMessage", containsString("bob")));

        // Verify share in DB
        List<DocumentShare> shares = documentShareRepository.findByDocumentId(doc.getId());
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getGrantee().getUsername()).isEqualTo("bob");
        assertThat(shares.get(0).getPermission()).isEqualTo(SharePermission.READ);

        // Verify audit event
        List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_GRANT);
        assertThat(events).anyMatch(e -> "alice".equals(e.getActorUsername()) && "bob".equals(e.getTargetUsername()));
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: owner grants EDIT permission successfully")
    void testOwnerSharesDocumentWithEditPermissionSuccess() throws Exception {
        Document doc = documentService.createDocument("Alice Share Edit Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "EDIT")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("successMessage", containsString("bob")));

        List<DocumentShare> shares = documentShareRepository.findByDocumentId(doc.getId());
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getGrantee().getUsername()).isEqualTo("bob");
        assertThat(shares.get(0).getPermission()).isEqualTo(SharePermission.EDIT);
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: sharing with nonexistent user fails with validation error")
    void testOwnerSharesWithNonexistentUserFails() throws Exception {
        Document doc = documentService.createDocument("Alice Ghost Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "ghost_user")
                        .param("permission", "READ")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("errorMessage", containsString("Grantee user not found: ghost_user")));

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).isEmpty();
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: owner cannot share with themselves")
    void testOwnerCannotShareWithSelf() throws Exception {
        Document doc = documentService.createDocument("Alice Self Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "alice")
                        .param("permission", "READ")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("errorMessage", containsString("Document owners cannot grant access to themselves")));

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).isEmpty();
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: blank recipient username fails validation")
    void testShareWithBlankUsernameFails() throws Exception {
        Document doc = documentService.createDocument("Alice Blank User Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "   ")
                        .param("permission", "READ")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("errorMessage", containsString("Recipient username is required")));

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).isEmpty();
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: duplicate share updates permission gracefully without duplicate rows")
    void testDuplicateShareUpdatesPermissionGracefully() throws Exception {
        Document doc = documentService.createDocument("Alice Upsert Doc", "Desc", "alice");

        // Initial READ share
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "READ")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound());

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).hasSize(1);
        assertThat(documentShareRepository.findByDocumentId(doc.getId()).get(0).getPermission()).isEqualTo(SharePermission.READ);

        // Update to EDIT share
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "EDIT")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("successMessage", containsString("updated")));

        // Verify still exactly 1 share row, now EDIT
        List<DocumentShare> shares = documentShareRepository.findByDocumentId(doc.getId());
        assertThat(shares).hasSize(1);
        assertThat(shares.get(0).getPermission()).isEqualTo(SharePermission.EDIT);

        // Verify audit event SHARE_UPDATE
        List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_UPDATE);
        assertThat(events).anyMatch(e -> "alice".equals(e.getActorUsername()) && "bob".equals(e.getTargetUsername()));
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: unauthorized non-owner cannot share document (403 for collaborator, 404 for unshared)")
    void testUnauthorizedUserCannotShareDocument() throws Exception {
        Document doc = documentService.createDocument("Alice Protected Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        // Bob (EDIT collaborator) attempts to share Alice's document -> 403 Forbidden
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "admin")
                        .param("permission", "READ")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        // Admin (unshared user) attempts to share Alice's document -> 404 Not Found (anti-IDOR)
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "READ")
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /documents/{id}/shares: request without CSRF is rejected with 403 Forbidden")
    void testShareWithoutCsrfRejected() throws Exception {
        Document doc = documentService.createDocument("Alice CSRF Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares")
                        .param("granteeUsername", "bob")
                        .param("permission", "READ")
                        .with(user("alice")))
                .andExpect(status().isForbidden());

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).isEmpty();
    }

    @Test
    @DisplayName("POST /documents/{id}/shares/revoke: owner revokes share successfully (PRG & Audit)")
    void testOwnerRevokesShareSuccess() throws Exception {
        Document doc = documentService.createDocument("Alice Revoke Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares/revoke")
                        .param("granteeUsername", "bob")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("successMessage", containsString("bob")));

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).isEmpty();

        List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.SHARE_REVOKE);
        assertThat(events).anyMatch(e -> "alice".equals(e.getActorUsername()) && "bob".equals(e.getTargetUsername()));
    }

    @Test
    @DisplayName("POST /documents/{id}/shares/revoke: immediate access denial after revocation")
    void testImmediateAccessDenialAfterRevocation() throws Exception {
        Document doc = documentService.createDocument("Alice Timely Revoke Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        // Bob can initially access
        mockMvc.perform(get("/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isOk());

        // Alice revokes Bob's access
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares/revoke")
                        .param("granteeUsername", "bob")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound());

        // Immediately after revocation, Bob cannot view the document (404 anti-IDOR)
        mockMvc.perform(get("/documents/" + doc.getId()).with(user("bob")))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /documents/{id}/shares/revoke: unauthorized user cannot revoke share (403 for collaborator, 404 for unshared)")
    void testUnauthorizedUserCannotRevokeShare() throws Exception {
        Document doc = documentService.createDocument("Alice Owner Revoke Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");
        User carol = userService.createUser("carol", "Password123!", "carol@example.com", Role.ROLE_USER);
        documentShareService.grantAccess(doc.getId(), "carol", SharePermission.EDIT, "alice");

        // Carol (EDIT collaborator) attempts to revoke Bob's share -> 403 Forbidden
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares/revoke")
                        .param("granteeUsername", "bob")
                        .with(user("carol"))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        // Admin (unshared user) attempts to revoke Bob's share -> 404 Not Found (anti-IDOR)
        mockMvc.perform(post("/documents/" + doc.getId() + "/shares/revoke")
                        .param("granteeUsername", "bob")
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /documents/{id}/shares/revoke: request without CSRF is rejected with 403 Forbidden")
    void testRevokeWithoutCsrfRejected() throws Exception {
        Document doc = documentService.createDocument("Alice Revoke CSRF Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/shares/revoke")
                        .param("granteeUsername", "bob")
                        .with(user("alice")))
                .andExpect(status().isForbidden());

        assertThat(documentShareRepository.findByDocumentId(doc.getId())).hasSize(1);
    }

    // =========================================================================
    // Search & Filter Tests
    // =========================================================================

    @Test
    @DisplayName("GET /documents?q=...: filters accessible documents by title/description without leaking unshared documents")
    void testSearchAndFilterQuery() throws Exception {
        Document d1 = documentService.createDocument("Annual Tax Statement", "Official tax report", "alice");
        Document d2 = documentService.createDocument("Project Roadmap", "Upcoming engineering plans", "alice");
        Document unsharedDoc = documentService.createDocument("Annual Bonus Pool", "Executive confidential", "bob");

        // Alice searches "tax"
        mockMvc.perform(get("/documents").param("q", "tax").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(model().attribute("searchQuery", "tax"))
                .andExpect(content().string(containsString("Annual Tax Statement")))
                .andExpect(content().string(not(containsString("Project Roadmap"))))
                .andExpect(content().string(not(containsString("Annual Bonus Pool"))));

        // Alice searches "bonus" (Bob's private document) -> must yield empty results, zero leakage
        mockMvc.perform(get("/documents").param("q", "bonus").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("No documents found")))
                .andExpect(content().string(not(containsString("Annual Bonus Pool"))));
    }

    @Test
    @DisplayName("GET /documents?owner=...: filters accessible documents by owner username")
    void testFilterByOwner() throws Exception {
        Document d1 = documentService.createDocument("Alice Strategy", "Desc", "alice");
        Document d2 = documentService.createDocument("Bob Joint Proposal", "Desc", "bob");
        documentShareService.grantAccess(d2.getId(), "alice", SharePermission.READ, "bob");

        mockMvc.perform(get("/documents").param("owner", "bob").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Bob Joint Proposal")))
                .andExpect(content().string(not(containsString("Alice Strategy"))));
    }

    // =========================================================================
    // Web Document Editing Tests (POST /documents/{id}/edit)
    // =========================================================================

    @Test
    @DisplayName("POST /documents/{id}/edit: owner can edit document metadata successfully")
    void testOwnerCanEditDocumentViaWeb() throws Exception {
        Document doc = documentService.createDocument("Original Title", "Original Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/edit")
                        .param("title", "Updated Title")
                        .param("description", "Updated Desc")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("successMessage", containsString("successfully updated")));

        Document updated = documentRepository.findById(doc.getId()).orElseThrow();
        assertThat(updated.getTitle()).isEqualTo("Updated Title");
        assertThat(updated.getDescription()).isEqualTo("Updated Desc");
    }

    @Test
    @DisplayName("POST /documents/{id}/edit: EDIT collaborator can edit document metadata")
    void testEditCollaboratorCanEditDocumentViaWeb() throws Exception {
        Document doc = documentService.createDocument("Shared Spec", "Original Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/edit")
                        .param("title", "Updated by Bob")
                        .param("description", "Edited Content")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attribute("successMessage", containsString("successfully updated")));

        Document updated = documentRepository.findById(doc.getId()).orElseThrow();
        assertThat(updated.getTitle()).isEqualTo("Updated by Bob");
    }

    @Test
    @DisplayName("POST /documents/{id}/edit: READ collaborator cannot edit document (403 Forbidden)")
    void testReadCollaboratorCannotEditDocumentViaWeb() throws Exception {
        Document doc = documentService.createDocument("Read Only Document", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/edit")
                        .param("title", "Tampered Title")
                        .param("description", "Tampered Desc")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        Document unchanged = documentRepository.findById(doc.getId()).orElseThrow();
        assertThat(unchanged.getTitle()).isEqualTo("Read Only Document");
    }

    @Test
    @DisplayName("POST /documents/{id}/edit: unshared user receives 404 anti-IDOR")
    void testUnsharedUserCannotEditDocumentViaWeb() throws Exception {
        Document doc = documentService.createDocument("Private Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/edit")
                        .param("title", "Tampered Title")
                        .with(user("admin"))
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("POST /documents/{id}/edit: blank title fails validation and redirects with error flash")
    void testEditDocumentValidationFailure() throws Exception {
        Document doc = documentService.createDocument("Valid Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/edit")
                        .param("title", "   ")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents/" + doc.getId()))
                .andExpect(flash().attributeExists("errorMessage"));
    }

    // =========================================================================
    // Web Document Deletion Tests (POST /documents/{id}/delete)
    // =========================================================================

    @Test
    @DisplayName("POST /documents/{id}/delete: owner can delete document successfully")
    void testOwnerCanDeleteDocumentViaWeb() throws Exception {
        Document doc = documentService.createDocument("Doc to Delete", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/delete")
                        .with(user("alice"))
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/documents"))
                .andExpect(flash().attribute("successMessage", containsString("successfully deleted")));

        assertThat(documentRepository.findById(doc.getId())).isEmpty();

        List<AuditEvent> deleteEvents = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.DOCUMENT_DELETE);
        assertThat(deleteEvents).anyMatch(e -> "alice".equals(e.getActorUsername()) && doc.getId().equals(e.getDocumentId()));
    }

    @Test
    @DisplayName("POST /documents/{id}/delete: EDIT collaborator cannot delete document (403 Forbidden)")
    void testEditCollaboratorCannotDeleteDocumentViaWeb() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Desc", "alice");
        documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/delete")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isForbidden());

        assertThat(documentRepository.findById(doc.getId())).isPresent();
    }

    @Test
    @DisplayName("POST /documents/{id}/delete: unshared user receives 404 anti-IDOR")
    void testUnsharedUserCannotDeleteDocumentViaWeb() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/delete")
                        .with(user("bob"))
                        .with(csrf()))
                .andExpect(status().isNotFound());

        assertThat(documentRepository.findById(doc.getId())).isPresent();
    }

    @Test
    @DisplayName("POST /documents/{id}/delete: request without CSRF is rejected with 403 Forbidden")
    void testDeleteWithoutCsrfRejected() throws Exception {
        Document doc = documentService.createDocument("Alice Doc", "Desc", "alice");

        mockMvc.perform(post("/documents/" + doc.getId() + "/delete")
                        .with(user("alice")))
                .andExpect(status().isForbidden());

        assertThat(documentRepository.findById(doc.getId())).isPresent();
    }
}
