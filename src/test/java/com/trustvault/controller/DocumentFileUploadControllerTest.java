package com.trustvault.controller;

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
import com.trustvault.storage.FileValidationService;
import com.trustvault.storage.StorageService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the secure document file upload endpoint:
 * {@code POST /api/documents/{id}/file}.
 *
 * Verifies:
 * - Successful upload by document owner returns HTTP 200 OK and safe DocumentResponseDto.
 * - Successful upload by EDIT collaborator returns HTTP 200 OK.
 * - READ collaborator upload attempt is rejected with HTTP 403 Forbidden.
 * - Unshared user upload attempt is rejected with HTTP 404 Not Found (anti-IDOR).
 * - ROLE_ADMIN without explicit share grant is rejected with HTTP 404 Not Found.
 * - Unauthenticated requests are rejected with HTTP 401 Unauthorized.
 * - Requests without valid CSRF token are rejected with HTTP 403 Forbidden.
 * - Invalid file contents (magic byte mismatch, missing parts, empty files) return HTTP 400 Bad Request.
 * - Oversized uploads exceeding 10 MiB limit are rejected with HTTP 400 Bad Request.
 * - Response DTO strictly suppresses physical storage keys, paths, checksums, and binary contents.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DocumentFileUploadControllerTest {

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
    private User admin;

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
        admin = userService.createUser("admin", "Password123!", "admin@example.com", Role.ROLE_ADMIN);
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

    @Nested
    @DisplayName("1. Successful Upload Scenarios")
    class SuccessfulUploadTests {

        @Test
        @DisplayName("POST /api/documents/{id}/file: owner can upload file and receives safe DocumentResponseDto")
        void testOwnerUploadSuccess() throws Exception {
            Document doc = documentService.createDocument("Alice Tax Return", "Financial records", "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "tax_return.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(user("alice"))
                    .with(csrf()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(doc.getId().intValue())))
                    .andExpect(jsonPath("$.title", is("Alice Tax Return")))
                    .andExpect(jsonPath("$.description", is("Financial records")))
                    .andExpect(jsonPath("$.ownerUsername", is("alice")))
                    .andExpect(jsonPath("$.hasFile", is(true)))
                    .andExpect(jsonPath("$.fileOriginalName", is("tax_return.pdf")))
                    .andExpect(jsonPath("$.fileContentType", is("application/pdf")))
                    .andExpect(jsonPath("$.fileSize", is(VALID_PDF.length)))
                    .andExpect(jsonPath("$.fileUploadedAt", notNullValue()))
                    .andExpect(jsonPath("$.storageKey", notNullValue()));
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: EDIT collaborator can upload and replace file")
        void testEditCollaboratorUploadSuccess() throws Exception {
            Document doc = documentService.createDocument("Shared Design", "System architecture", "alice");
            documentShareService.grantAccess(doc.getId(), "bob", SharePermission.EDIT, "alice");

            MockMultipartFile pngFile = new MockMultipartFile(
                    "file",
                    "architecture.png",
                    "image/png",
                    VALID_PNG
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(pngFile)
                    .with(user("bob"))
                    .with(csrf()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id", is(doc.getId().intValue())))
                    .andExpect(jsonPath("$.hasFile", is(true)))
                    .andExpect(jsonPath("$.fileOriginalName", is("architecture.png")))
                    .andExpect(jsonPath("$.fileContentType", is("image/png")))
                    .andExpect(jsonPath("$.fileSize", is(VALID_PNG.length)));
        }
    }

    @Nested
    @DisplayName("2. Safe Response Fields & Information Disclosure Prevention")
    class SafeResponseFieldsTests {

        @Test
        @DisplayName("POST /api/documents/{id}/file: response suppresses physical storage keys, paths, and checksums")
        void testResponseSuppressesSensitiveInternalData() throws Exception {
            Document doc = documentService.createDocument("Private Audit", "Sensitive internal review", "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "audit.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(user("alice"))
                    .with(csrf()))
                    .andExpect(status().isOk())
                    // Must expose safe client fields
                    .andExpect(jsonPath("$.storageKey", notNullValue()))
                    .andExpect(jsonPath("$.hasFile", is(true)))
                    // Must strictly NOT expose physical blob UUIDs, internal checksums, or disk paths
                    .andExpect(jsonPath("$.fileStorageKey").doesNotExist())
                    .andExpect(jsonPath("$.fileChecksum").doesNotExist())
                    .andExpect(jsonPath("$.filePath").doesNotExist())
                    .andExpect(jsonPath("$.path").doesNotExist())
                    .andExpect(jsonPath("$.diskLocation").doesNotExist())
                    .andExpect(jsonPath("$.content").doesNotExist());
        }
    }

    @Nested
    @DisplayName("3. Authorization & Access Control")
    class AuthorizationAndAccessControlTests {

        @Test
        @DisplayName("POST /api/documents/{id}/file: READ collaborator is rejected with HTTP 403 Forbidden")
        void testReadCollaboratorDeniedWith403() throws Exception {
            Document doc = documentService.createDocument("Read Only Vault", "Confidential", "alice");
            documentShareService.grantAccess(doc.getId(), "carol", SharePermission.READ, "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "unauthorized.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(user("carol"))
                    .with(csrf()))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.status", is(403)))
                    .andExpect(jsonPath("$.error", is("Forbidden")))
                    .andExpect(jsonPath("$.message", containsString("Access is denied")));
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: unshared user is rejected with HTTP 404 anti-IDOR")
        void testUnsharedUserDeniedWith404() throws Exception {
            Document doc = documentService.createDocument("Secret Vault", "Secret details", "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "probe.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(user("mallory"))
                    .with(csrf()))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status", is(404)))
                    .andExpect(jsonPath("$.error", is("Not Found")))
                    .andExpect(jsonPath("$.message", containsString("Document not found")));
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: ROLE_ADMIN without explicit share grant receives HTTP 404 anti-IDOR")
        void testAdminWithoutShareGrantDeniedWith404() throws Exception {
            Document doc = documentService.createDocument("Alice Private Financials", "Restricted", "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "admin_override.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(user("admin").roles("ADMIN"))
                    .with(csrf()))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status", is(404)))
                    .andExpect(jsonPath("$.error", is("Not Found")))
                    .andExpect(jsonPath("$.message", containsString("Document not found")));
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: unauthenticated request is rejected with HTTP 401 Unauthorized")
        void testUnauthenticatedRequestDeniedWith401() throws Exception {
            Document doc = documentService.createDocument("Public Probe Doc", "Public description", "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "anonymous.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(csrf()))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("4. CSRF Protection Enforcements")
    class CsrfProtectionTests {

        @Test
        @DisplayName("POST /api/documents/{id}/file: missing CSRF token rejected with HTTP 403 Forbidden")
        void testMissingCsrfTokenRejected() throws Exception {
            Document doc = documentService.createDocument("CSRF Test Doc", "Description", "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "test.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(user("alice")))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: invalid CSRF token rejected with HTTP 403 Forbidden")
        void testInvalidCsrfTokenRejected() throws Exception {
            Document doc = documentService.createDocument("CSRF Invalid Doc", "Description", "alice");

            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "test.pdf",
                    "application/pdf",
                    VALID_PDF
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(file)
                    .with(user("alice"))
                    .with(csrf().useInvalidToken()))
                    .andExpect(status().isForbidden());
        }
    }

    @Nested
    @DisplayName("5. File Validation & Limit Enforcements")
    class FileValidationAndLimitsTests {

        @Test
        @DisplayName("POST /api/documents/{id}/file: spoofed MIME type rejected with HTTP 400 Bad Request")
        void testMimeSpoofingRejected() throws Exception {
            Document doc = documentService.createDocument("Spoof Doc", "Description", "alice");

            // PNG bytes declared as PDF
            MockMultipartFile spoofed = new MockMultipartFile(
                    "file",
                    "malicious.pdf",
                    "application/pdf",
                    VALID_PNG
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(spoofed)
                    .with(user("alice"))
                    .with(csrf()))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status", is(400)))
                    .andExpect(jsonPath("$.error", is("Bad Request")))
                    .andExpect(jsonPath("$.message", containsString("File content does not match PDF signature")));
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: missing file part rejected with HTTP 400 Bad Request")
        void testMissingFilePartRejected() throws Exception {
            Document doc = documentService.createDocument("Empty Part Doc", "Description", "alice");

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .with(user("alice"))
                    .with(csrf()))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status", is(400)))
                    .andExpect(jsonPath("$.error", is("Bad Request")))
                    .andExpect(jsonPath("$.message", containsString("Upload file payload must not be null")));
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: empty file payload (0 bytes) rejected with HTTP 400 Bad Request")
        void testEmptyFilePayloadRejected() throws Exception {
            Document doc = documentService.createDocument("Zero Byte Doc", "Description", "alice");

            MockMultipartFile emptyFile = new MockMultipartFile(
                    "file",
                    "empty.pdf",
                    "application/pdf",
                    new byte[0]
            );

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(emptyFile)
                    .with(user("alice"))
                    .with(csrf()))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status", is(400)))
                    .andExpect(jsonPath("$.error", is("Bad Request")))
                    .andExpect(jsonPath("$.message", containsString("File must not be empty")));
        }

        @Test
        @DisplayName("POST /api/documents/{id}/file: oversized upload (> 10 MiB) rejected with HTTP 400 Bad Request")
        void testOversizedUploadRejected() throws Exception {
            Document doc = documentService.createDocument("Large File Doc", "Description", "alice");

            long oversizedLength = FileValidationService.MAX_FILE_SIZE_BYTES + 1L; // 10,485,761 bytes
            MockMultipartFile oversizedFile = new MockMultipartFile(
                    "file",
                    "huge.pdf",
                    "application/pdf",
                    VALID_PDF
            ) {
                @Override
                public long getSize() {
                    return oversizedLength;
                }
            };

            mockMvc.perform(multipart("/api/documents/{id}/file", doc.getId())
                    .file(oversizedFile)
                    .with(user("alice"))
                    .with(csrf()))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status", is(400)))
                    .andExpect(jsonPath("$.error", is("Bad Request")))
                    .andExpect(jsonPath("$.message", containsString("exceeds maximum permitted limit of 10 MiB")));
        }
    }
}
