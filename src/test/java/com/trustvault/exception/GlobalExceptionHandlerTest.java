package com.trustvault.exception;

import com.trustvault.dto.ErrorResponseDto;
import com.trustvault.storage.FileValidationException;
import com.trustvault.storage.StorageException;
import com.trustvault.storage.StorageFileNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.servlet.MultipartProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.unit.DataSize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link GlobalExceptionHandler} and multipart configuration.
 *
 * Verifies:
 * - MaxUploadSizeExceededException maps to HTTP 413 Payload Too Large.
 * - FileValidationException maps to HTTP 400 Bad Request.
 * - StorageException maps to a sanitized HTTP 500 without internal path leakage.
 * - StorageFileNotFoundException maps to a sanitized HTTP 404 without internal path leakage.
 * - Existing exception handlers (AccessDenied, ResourceNotFound, IllegalArgument, Generic) remain intact.
 * - MultipartProperties configuration specifies 10 MiB max-file-size and 11 MiB max-request-size.
 */
@SpringBootTest
class GlobalExceptionHandlerTest {

    @Autowired
    private MultipartProperties multipartProperties;

    private GlobalExceptionHandler exceptionHandler;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        exceptionHandler = new GlobalExceptionHandler();
        mockMvc = MockMvcBuilders.standaloneSetup(new TestExceptionController())
                .setControllerAdvice(exceptionHandler)
                .build();
    }

    @Nested
    @DisplayName("1. Multipart Configuration Tests")
    class MultipartConfigTests {

        @Test
        @DisplayName("MultipartProperties: max-file-size should be exactly 10 MiB (10,485,760 bytes)")
        void testMaxFileSizeConfigured() {
            assertThat(multipartProperties.getMaxFileSize())
                    .isEqualTo(DataSize.ofMegabytes(10));
            assertThat(multipartProperties.getMaxFileSize().toBytes())
                    .isEqualTo(10L * 1024L * 1024L);
        }

        @Test
        @DisplayName("MultipartProperties: max-request-size should be 11 MiB (11,534,336 bytes) to allow multipart overhead")
        void testMaxRequestSizeConfigured() {
            assertThat(multipartProperties.getMaxRequestSize())
                    .isEqualTo(DataSize.ofMegabytes(11));
            assertThat(multipartProperties.getMaxRequestSize().toBytes())
                    .isEqualTo(11L * 1024L * 1024L);
        }
    }

    @Nested
    @DisplayName("2. Storage & Upload Exception Handler Tests")
    class StorageAndUploadHandlerTests {

        @Test
        @DisplayName("handleMaxUploadSizeExceeded: should return HTTP 413 Payload Too Large")
        void testMaxUploadSizeExceededDirect() {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/documents/upload");
            MaxUploadSizeExceededException ex = new MaxUploadSizeExceededException(10L * 1024L * 1024L);

            ResponseEntity<ErrorResponseDto> response = exceptionHandler.handleMaxUploadSizeExceeded(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
            ErrorResponseDto body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.status()).isEqualTo(413);
            assertThat(body.error()).isEqualTo("Payload Too Large");
            assertThat(body.message()).isEqualTo("Upload payload exceeds the maximum permitted size limit of 10 MiB.");
            assertThat(body.path()).isEqualTo("/api/documents/upload");
        }

        @Test
        @DisplayName("handleFileValidation: should return HTTP 400 Bad Request with validation message")
        void testFileValidationDirect() {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/documents/upload");
            FileValidationException ex = new FileValidationException("File content does not match PDF signature ('%PDF-')");

            ResponseEntity<ErrorResponseDto> response = exceptionHandler.handleFileValidation(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            ErrorResponseDto body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.status()).isEqualTo(400);
            assertThat(body.error()).isEqualTo("Bad Request");
            assertThat(body.message()).isEqualTo("File content does not match PDF signature ('%PDF-')");
            assertThat(body.path()).isEqualTo("/api/documents/upload");
        }

        @Test
        @DisplayName("handleStorageFileNotFound: should return HTTP 404 Not Found with sanitized message")
        void testStorageFileNotFoundDirect() {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/documents/123/download");
            StorageFileNotFoundException ex = new StorageFileNotFoundException(
                    "Document file blob not found for storage key: 8f9b1c2d-3e4f-5a6b-7c8d-9e0f1a2b3c4d");

            ResponseEntity<ErrorResponseDto> response = exceptionHandler.handleStorageFileNotFound(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            ErrorResponseDto body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.status()).isEqualTo(404);
            assertThat(body.error()).isEqualTo("Not Found");
            assertThat(body.message()).isEqualTo("The requested document file could not be found.");
            assertThat(body.message()).doesNotContain("8f9b1c2d");
            assertThat(body.path()).isEqualTo("/api/documents/123/download");
        }

        @Test
        @DisplayName("handleStorage: should return sanitized HTTP 500 without leaking private filesystem paths")
        void testStorageExceptionDirectSanitized() {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/documents/upload");
            StorageException ex = new StorageException(
                    "Failed to write to private directory C:\\TrustVault\\private-storage\\uploads\\tv_upload_abc.tmp: Disk full");

            ResponseEntity<ErrorResponseDto> response = exceptionHandler.handleStorage(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            ErrorResponseDto body = response.getBody();
            assertThat(body).isNotNull();
            assertThat(body.status()).isEqualTo(500);
            assertThat(body.error()).isEqualTo("Internal Server Error");
            assertThat(body.message()).isEqualTo("A storage error occurred while processing the document file.");
            assertThat(body.message()).doesNotContain("C:\\TrustVault");
            assertThat(body.message()).doesNotContain("private-storage");
            assertThat(body.message()).doesNotContain("Disk full");
            assertThat(body.path()).isEqualTo("/api/documents/upload");
        }
    }

    @Nested
    @DisplayName("3. End-to-End MockMvc Controller Advice Integration")
    class MockMvcIntegrationTests {

        @Test
        @DisplayName("MockMvc: MaxUploadSizeExceededException maps to HTTP 413 Payload Too Large")
        void testMockMvcMaxUploadSize() throws Exception {
            mockMvc.perform(get("/test/max-upload-size").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isPayloadTooLarge())
                    .andExpect(jsonPath("$.status", is(413)))
                    .andExpect(jsonPath("$.error", is("Payload Too Large")))
                    .andExpect(jsonPath("$.message", is("Upload payload exceeds the maximum permitted size limit of 10 MiB.")))
                    .andExpect(jsonPath("$.path", is("/test/max-upload-size")));
        }

        @Test
        @DisplayName("MockMvc: FileValidationException maps to HTTP 400 Bad Request")
        void testMockMvcFileValidation() throws Exception {
            mockMvc.perform(get("/test/file-validation").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status", is(400)))
                    .andExpect(jsonPath("$.error", is("Bad Request")))
                    .andExpect(jsonPath("$.message", is("DOCX archive is missing required '[Content_Types].xml' entry")))
                    .andExpect(jsonPath("$.path", is("/test/file-validation")));
        }

        @Test
        @DisplayName("MockMvc: StorageFileNotFoundException maps to HTTP 404 Not Found")
        void testMockMvcStorageFileNotFound() throws Exception {
            mockMvc.perform(get("/test/storage-not-found").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status", is(404)))
                    .andExpect(jsonPath("$.error", is("Not Found")))
                    .andExpect(jsonPath("$.message", is("The requested document file could not be found.")))
                    .andExpect(jsonPath("$.message", not(containsString("internal-storage"))))
                    .andExpect(jsonPath("$.path", is("/test/storage-not-found")));
        }

        @Test
        @DisplayName("MockMvc: StorageException maps to sanitized HTTP 500 Internal Server Error")
        void testMockMvcStorageError() throws Exception {
            mockMvc.perform(get("/test/storage-error").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.status", is(500)))
                    .andExpect(jsonPath("$.error", is("Internal Server Error")))
                    .andExpect(jsonPath("$.message", is("A storage error occurred while processing the document file.")))
                    .andExpect(jsonPath("$.message", not(containsString("sensitive-root"))))
                    .andExpect(jsonPath("$.path", is("/test/storage-error")));
        }

        @Test
        @DisplayName("MockMvc: AccessDeniedException maps to HTTP 403 Forbidden (existing behavior preserved)")
        void testMockMvcAccessDenied() throws Exception {
            mockMvc.perform(get("/test/access-denied").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.status", is(403)))
                    .andExpect(jsonPath("$.error", is("Forbidden")))
                    .andExpect(jsonPath("$.path", is("/test/access-denied")));
        }

        @Test
        @DisplayName("MockMvc: ResourceNotFoundException maps to HTTP 404 Not Found (existing behavior preserved)")
        void testMockMvcResourceNotFound() throws Exception {
            mockMvc.perform(get("/test/resource-not-found").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.status", is(404)))
                    .andExpect(jsonPath("$.error", is("Not Found")))
                    .andExpect(jsonPath("$.message", is("Document 42 not found")))
                    .andExpect(jsonPath("$.path", is("/test/resource-not-found")));
        }

        @Test
        @DisplayName("MockMvc: IllegalArgumentException maps to HTTP 400 Bad Request (existing behavior preserved)")
        void testMockMvcIllegalArgument() throws Exception {
            mockMvc.perform(get("/test/illegal-argument").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status", is(400)))
                    .andExpect(jsonPath("$.error", is("Bad Request")))
                    .andExpect(jsonPath("$.message", is("Invalid argument provided")))
                    .andExpect(jsonPath("$.path", is("/test/illegal-argument")));
        }

        @Test
        @DisplayName("MockMvc: Generic Exception maps to sanitized HTTP 500 (existing behavior preserved)")
        void testMockMvcGenericException() throws Exception {
            mockMvc.perform(get("/test/generic-exception").accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.status", is(500)))
                    .andExpect(jsonPath("$.error", is("Internal Server Error")))
                    .andExpect(jsonPath("$.message", is("An unexpected internal error occurred. Please contact system administrator.")))
                    .andExpect(jsonPath("$.path", is("/test/generic-exception")));
        }
    }

    /**
     * Isolated test controller to trigger specific exceptions for MockMvc verification.
     */
    @RestController
    static class TestExceptionController {

        @GetMapping("/test/max-upload-size")
        void throwMaxUploadSize() {
            throw new MaxUploadSizeExceededException(10L * 1024L * 1024L);
        }

        @GetMapping("/test/file-validation")
        void throwFileValidation() {
            throw new FileValidationException("DOCX archive is missing required '[Content_Types].xml' entry");
        }

        @GetMapping("/test/storage-not-found")
        void throwStorageFileNotFound() {
            throw new StorageFileNotFoundException("File missing in /var/internal-storage/tv_123.bin");
        }

        @GetMapping("/test/storage-error")
        void throwStorageError() {
            throw new StorageException("Filesystem failure in /etc/sensitive-root/storage");
        }

        @GetMapping("/test/access-denied")
        void throwAccessDenied() {
            throw new AccessDeniedException("Access denied by security rule");
        }

        @GetMapping("/test/resource-not-found")
        void throwResourceNotFound() {
            throw new ResourceNotFoundException("Document 42 not found");
        }

        @GetMapping("/test/illegal-argument")
        void throwIllegalArgument() {
            throw new IllegalArgumentException("Invalid argument provided");
        }

        @GetMapping("/test/generic-exception")
        void throwGenericException() {
            throw new RuntimeException("Unexpected database connection crash");
        }
    }
}
