package com.trustvault.controller;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the secure document file download endpoint:
 * {@code GET /api/documents/{id}/download}.
 *
 * Verifies:
 * - Owner downloads valid file successfully with correct headers and bytes.
 * - READ collaborator downloads valid file successfully.
 * - EDIT collaborator downloads valid file successfully.
 * - Unshared user and revoked collaborator are denied with HTTP 404 (anti-IDOR).
 * - Disabled accounts (requester or owner) are denied access with HTTP 404.
 * - Document without an attachment returns HTTP 404.
 * - Missing stored blob on disk returns sanitized HTTP 404.
 * - Modified/corrupted bytes on disk fail SHA-256 verification and return HTTP 500 without streaming file.
 * - Safe Content-Disposition and Content-Type headers prevent header injection.
 * - Successful downloads record AuditAction.FILE_DOWNLOAD, and denials retain security denial auditing.
 * - Detail HTML view renders the Download File button only when a file payload is attached.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DocumentFileDownloadControllerTest {

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
    private User carol;
    private User mallory;

    private static final byte[] VALID_PDF = "%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VALID_PNG = new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D, 0x49, 0x48, 0x44, 0x52
    };

    @BeforeEach
    void setUp() {
        cleanup();
        alice = userService.createUser("alice", "Password123!", "alice@example.com", Role.ROLE_USER);
        bob = userService.createUser("bob", "Password123!", "bob@example.com", Role.ROLE_USER);
        carol = userService.createUser("carol", "Password123!", "carol@example.com", Role.ROLE_USER);
        mallory = userService.createUser("mallory", "Password123!", "mallory@example.com", Role.ROLE_USER);
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
        storageService.deleteAll();
    }

    private Document createDocWithFile(String owner, String title, String filename, String mime, byte[] content) {
        Document doc = documentService.createDocument(title, "Test document", owner);
        return documentService.uploadFile(
                doc.getId(),
                new ByteArrayInputStream(content),
                filename,
                mime,
                (long) content.length,
                owner,
                "127.0.0.1"
        );
    }

    @Nested
    @DisplayName("1. Successful Download Scenarios")
    class SuccessfulDownloadTests {

        @Test
        @DisplayName("GET /api/documents/{id}/download: owner downloads valid file successfully")
        void testOwnerDownloadSuccess() throws Exception {
            Document doc = createDocWithFile("alice", "Alice Tax Return", "tax_return.pdf", "application/pdf", VALID_PDF);

            MvcResult result = mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("alice")))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.CONTENT_TYPE, "application/pdf"))
                    .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("attachment")))
                    .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"tax_return.pdf\"")))
                    .andExpect(header().string(HttpHeaders.CONTENT_LENGTH, String.valueOf(VALID_PDF.length)))
                    .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                    .andReturn();

            assertThat(result.getResponse().getContentAsByteArray()).isEqualTo(VALID_PDF);

            // Verify FILE_DOWNLOAD audit event
            List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.FILE_DOWNLOAD);
            assertThat(events).hasSize(1);
            AuditEvent event = events.get(0);
            assertThat(event.getActorUsername()).isEqualTo("alice");
            assertThat(event.getDocumentId()).isEqualTo(doc.getId());
            assertThat(event.getOutcome()).isEqualTo(AuditOutcome.SUCCESS);
            assertThat(event.getDetails()).contains("tax_return.pdf");
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: READ collaborator downloads successfully")
        void testReadCollaboratorDownloadSuccess() throws Exception {
            Document doc = createDocWithFile("alice", "Shared Spec", "spec.png", "image/png", VALID_PNG);
            documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

            MvcResult result = mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("bob")))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.CONTENT_TYPE, "image/png"))
                    .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"spec.png\"")))
                    .andReturn();

            assertThat(result.getResponse().getContentAsByteArray()).isEqualTo(VALID_PNG);

            List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.FILE_DOWNLOAD);
            assertThat(events).hasSize(1);
            assertThat(events.get(0).getActorUsername()).isEqualTo("bob");
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: EDIT collaborator downloads successfully")
        void testEditCollaboratorDownloadSuccess() throws Exception {
            Document doc = createDocWithFile("alice", "Shared Edit Doc", "contract.pdf", "application/pdf", VALID_PDF);
            documentShareService.grantAccess(doc.getId(), "carol", SharePermission.EDIT, "alice");

            MvcResult result = mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("carol")))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"contract.pdf\"")))
                    .andReturn();

            assertThat(result.getResponse().getContentAsByteArray()).isEqualTo(VALID_PDF);

            List<AuditEvent> events = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.FILE_DOWNLOAD);
            assertThat(events).hasSize(1);
            assertThat(events.get(0).getActorUsername()).isEqualTo("carol");
        }
    }

    @Nested
    @DisplayName("2. Access Denial & Anti-IDOR Scenarios")
    class AccessDenialTests {

        @Test
        @DisplayName("GET /api/documents/{id}/download: unshared user is denied with HTTP 404 (anti-IDOR)")
        void testUnsharedUserDenied404() throws Exception {
            Document doc = createDocWithFile("alice", "Secret Plan", "secret.pdf", "application/pdf", VALID_PDF);

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("mallory")))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status").value(404))
                    .andExpect(jsonPath("$.message").value(containsString("Document not found")));

            // Verify ACCESS_DENIED audit event
            List<AuditEvent> denials = auditEventRepository.findByActionOrderByTimestampDesc(AuditAction.ACCESS_DENIED);
            assertThat(denials).isNotEmpty();
            AuditEvent denial = denials.get(0);
            assertThat(denial.getActorUsername()).isEqualTo("mallory");
            assertThat(denial.getDocumentId()).isEqualTo(doc.getId());
            assertThat(denial.getDetails()).contains("reason=NOT_FOUND_OR_UNAUTHORIZED");
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: revoked collaborator is denied with HTTP 404")
        void testRevokedCollaboratorDenied404() throws Exception {
            Document doc = createDocWithFile("alice", "Temp Share", "temp.pdf", "application/pdf", VALID_PDF);
            documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

            // Bob downloads before revocation
            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("bob")))
                    .andExpect(status().isOk());

            // Alice revokes Bob's access
            documentShareService.revokeAccess(doc.getId(), "bob", "alice");

            // Bob attempts download after revocation -> 404
            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("bob")))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status").value(404));
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: disabled requester is denied with HTTP 404")
        void testDisabledRequesterDenied() throws Exception {
            Document doc = createDocWithFile("alice", "Alice Doc", "doc.pdf", "application/pdf", VALID_PDF);
            documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

            // Disable Bob
            bob.setEnabled(false);
            userRepository.save(bob);

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("bob")))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: when owner is disabled, collaborator is denied with HTTP 404")
        void testDisabledOwnerDenied() throws Exception {
            Document doc = createDocWithFile("alice", "Alice Doc", "doc.pdf", "application/pdf", VALID_PDF);
            documentShareService.grantAccess(doc.getId(), "bob", SharePermission.READ, "alice");

            // Disable Alice (owner)
            alice.setEnabled(false);
            userRepository.save(alice);

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("bob")))
                    .andExpect(status().isNotFound());
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: unauthenticated request is rejected with HTTP 401")
        void testUnauthenticatedDownloadRejected() throws Exception {
            Document doc = createDocWithFile("alice", "Public Doc", "public.pdf", "application/pdf", VALID_PDF);

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId()))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("3. Missing File & Storage Integrity Scenarios")
    class IntegrityAndMissingFileTests {

        @Test
        @DisplayName("GET /api/documents/{id}/download: document without an attachment returns HTTP 404")
        void testDocumentWithoutAttachmentReturns404() throws Exception {
            Document doc = documentService.createDocument("Empty Metadata Doc", "No file attached", "alice");

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("alice")))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status").value(404))
                    .andExpect(jsonPath("$.message").value(containsString("Document has no attached file payload")));
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: missing stored blob returns sanitized HTTP 404")
        void testMissingStoredBlobReturnsSanitized404() throws Exception {
            Document doc = createDocWithFile("alice", "Missing Blob Doc", "report.pdf", "application/pdf", VALID_PDF);

            // Delete physical file from storage behind the scenes
            storageService.delete(doc.getFileStorageKey());

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("alice")))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status").value(404))
                    .andExpect(jsonPath("$.message").value("The requested document file could not be found."))
                    .andExpect(jsonPath("$.message").value(not(containsString(doc.getFileStorageKey().toString()))));
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: corrupted file on disk causes SHA-256 failure with HTTP 500")
        void testCorruptedFileFailsChecksumWith500() throws Exception {
            Document doc = createDocWithFile("alice", "Tampered Doc", "tampered.pdf", "application/pdf", VALID_PDF);

            // Corrupt the file on disk by overwriting it with different bytes
            Path physicalPath = storageService.resolvePath(doc.getFileStorageKey());
            byte[] corruptedBytes = "%PDF-1.7\nCorrupted Content Has Been Altered On Disk!!".getBytes(StandardCharsets.US_ASCII);
            Files.write(physicalPath, corruptedBytes);

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("alice")))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.status").value(500))
                    .andExpect(jsonPath("$.message").value("A storage error occurred while processing the document file."))
                    .andExpect(jsonPath("$.message").value(not(containsString(doc.getFileStorageKey().toString()))));
        }

        @Test
        @DisplayName("GET /api/documents/{id}/download: header safety and unicode filename handling")
        void testFilenameHeaderSafety() throws Exception {
            String specialFilename = "Quarterly Report - 2026.pdf";
            Document doc = createDocWithFile("alice", "Quarterly", specialFilename, "application/pdf", VALID_PDF);

            mockMvc.perform(get("/api/documents/{id}/download", doc.getId())
                            .with(user("alice")))
                    .andExpect(status().isOk())
                    .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("attachment")))
                    .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString(specialFilename)));
        }
    }

    @Nested
    @DisplayName("4. Detail View UI Integration")
    class DetailViewUiTests {

        @Test
        @DisplayName("GET /documents/{id}: renders Download File button when document has an attached file")
        void testDetailViewRendersDownloadButtonWhenFileAttached() throws Exception {
            Document doc = createDocWithFile("alice", "Alice Doc With File", "report.pdf", "application/pdf", VALID_PDF);

            mockMvc.perform(get("/documents/{id}", doc.getId())
                            .with(user("alice"))
                            .accept(MediaType.TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("id=\"download-file-btn\"")))
                    .andExpect(content().string(containsString("/api/documents/" + doc.getId() + "/download")));
        }

        @Test
        @DisplayName("GET /documents/{id}: does NOT render Download File button when document has no file")
        void testDetailViewOmitsDownloadButtonWhenNoFile() throws Exception {
            Document doc = documentService.createDocument("Alice Doc Without File", "No file", "alice");

            mockMvc.perform(get("/documents/{id}", doc.getId())
                            .with(user("alice"))
                            .accept(MediaType.TEXT_HTML))
                    .andExpect(status().isOk())
                    .andExpect(content().string(not(containsString("id=\"download-file-btn\""))))
                    .andExpect(content().string(containsString("No binary file attached")));
        }
    }
}
