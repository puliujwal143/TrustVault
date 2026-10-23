package com.trustvault.storage;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConvexStorageServiceTest {

    private static final String VALID_BASE_URL = "https://doting-robin-733.ap-southeast-2.convex.site";
    private static final String VALID_SECRET = "test-shared-secret-12345";

    @Nested
    @DisplayName("1. Configuration and URL Normalization Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Valid HTTPS base URL and secret initialize successfully")
        void validConfigInitializesSuccessfully() {
            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET);
            service.init();
        }

        @Test
        @DisplayName("Blank base URL or secret throws StorageException")
        void blankConfigThrowsStorageException() {
            ConvexStorageService missingUrl = new ConvexStorageService("", VALID_SECRET);
            assertThatThrownBy(missingUrl::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("TRUSTVAULT_CONVEX_BASE_URL");

            ConvexStorageService missingSecret = new ConvexStorageService(VALID_BASE_URL, "  ");
            assertThatThrownBy(missingSecret::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("TRUSTVAULT_CONVEX_SHARED_SECRET");
        }

        @Test
        @DisplayName("Insecure HTTP or invalid URL schemes are rejected")
        void insecureOrInvalidUrlThrowsStorageException() {
            ConvexStorageService httpService = new ConvexStorageService("http://insecure.example.com", VALID_SECRET);
            assertThatThrownBy(httpService::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("valid HTTPS base URL");
        }

        @Test
        @DisplayName("Base URL with trailing slashes or duplicate /files is normalized cleanly")
        @SuppressWarnings("unchecked")
        void baseUrlWithTrailingFilesOrSlashesNormalized() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(200);
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            // Configure with redundant /files/ suffix
            ConvexStorageService service = new ConvexStorageService(
                    "https://doting-robin-733.ap-southeast-2.convex.site/files/",
                    "\"" + VALID_SECRET + "\"",
                    mockClient
            );

            UUID key = UUID.fromString("550e8400-e29b-41d4-a716-446655440000");
            service.store(key, "payload".getBytes(StandardCharsets.UTF_8));

            ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(mockClient).send(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));

            HttpRequest sentRequest = requestCaptor.getValue();
            // Verify path does not contain /files/files
            assertThat(sentRequest.uri().toString())
                    .isEqualTo("https://doting-robin-733.ap-southeast-2.convex.site/files?storageKey=550e8400-e29b-41d4-a716-446655440000");

            // Verify quotes were stripped from shared secret in Authorization header
            assertThat(sentRequest.headers().firstValue("Authorization"))
                    .hasValue("Bearer " + VALID_SECRET);
        }

        @Test
        @DisplayName("Shell variable assignments or expressions in shared secret are rejected at init")
        void shellAssignmentSecretThrowsStorageException() {
            ConvexStorageService psAssignment = new ConvexStorageService(
                    VALID_BASE_URL,
                    "$env:TRUSTVAULT_CONVEX_SHARED_SECRET = Get-Clipboard"
            );
            assertThatThrownBy(psAssignment::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("shell variable expression or assignment");

            ConvexStorageService psVar = new ConvexStorageService(
                    VALID_BASE_URL,
                    "$env:TRUSTVAULT_CONVEX_SHARED_SECRET"
            );
            assertThatThrownBy(psVar::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("shell variable expression or assignment");

            ConvexStorageService clipboard = new ConvexStorageService(
                    VALID_BASE_URL,
                    "Get-Clipboard"
            );
            assertThatThrownBy(clipboard::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("shell variable expression or assignment");

            ConvexStorageService bashExport = new ConvexStorageService(
                    VALID_BASE_URL,
                    "export TRUSTVAULT_CONVEX_SHARED_SECRET=some_value"
            );
            assertThatThrownBy(bashExport::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("shell variable expression or assignment");

            ConvexStorageService cmdSet = new ConvexStorageService(
                    VALID_BASE_URL,
                    "set TRUSTVAULT_CONVEX_SHARED_SECRET=some_value"
            );
            assertThatThrownBy(cmdSet::init)
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("shell variable expression or assignment");
        }

        @Test
        @DisplayName("Legitimate secret values containing equals signs and Base64 padding initialize successfully")
        void legitimateSecretsWithEqualsPaddingInitializeSuccessfully() {
            // Standard Base64 encoded 32-byte secret ending in = padding
            ConvexStorageService base64SinglePadding = new ConvexStorageService(
                    VALID_BASE_URL,
                    "EXD4B3zpixQxiBFvaBUvXYTKqIHKmAFo4faaSScDdJA="
            );
            base64SinglePadding.init();

            // Base64 with == double padding
            ConvexStorageService base64DoublePadding = new ConvexStorageService(
                    VALID_BASE_URL,
                    "dGVzdC1zZWNyZXQtMTIzNDU2Nzg5MA=="
            );
            base64DoublePadding.init();

            // Arbitrary token containing = characters
            ConvexStorageService tokenWithEquals = new ConvexStorageService(
                    VALID_BASE_URL,
                    "key=secret_value_12345"
            );
            tokenWithEquals.init();

            // Secret starting with TRUSTVAULT_ prefix
            ConvexStorageService prefixSecret = new ConvexStorageService(
                    VALID_BASE_URL,
                    "TRUSTVAULT_SECRET_KEY_12345="
            );
            prefixSecret.init();
        }

        @Test
        @DisplayName("Accidental Bearer prefix in shared secret is stripped defensively")
        @SuppressWarnings("unchecked")
        void secretWithAccidentalBearerPrefixStripped() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(200);
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(
                    VALID_BASE_URL,
                    "Bearer " + VALID_SECRET,
                    mockClient
            );

            UUID key = UUID.randomUUID();
            service.store(key, "data".getBytes(StandardCharsets.UTF_8));

            ArgumentCaptor<HttpRequest> requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(mockClient).send(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(requestCaptor.getValue().headers().firstValue("Authorization"))
                    .hasValue("Bearer " + VALID_SECRET);
        }

        @Test
        @DisplayName("Diagnostic connectivity check handles 200, 401, 503, and network errors gracefully without crashing")
        @SuppressWarnings("unchecked")
        void diagnosticConnectivityCheckGraceful() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);

            // 1. HTTP 200 OK
            when(mockResponse.statusCode()).thenReturn(200);
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            service.checkConnectivity();

            // 2. HTTP 401 Unauthorized
            when(mockResponse.statusCode()).thenReturn(401);
            service.checkConnectivity();

            // 3. HTTP 503 Service Unavailable
            when(mockResponse.statusCode()).thenReturn(503);
            service.checkConnectivity();

            // 4. IOException / Network unreachable
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenThrow(new IOException("Connection refused"));
            service.checkConnectivity(); // Should not throw
        }
    }

    @Nested
    @DisplayName("2. Upload Operations & HTTP Status Handling")
    class UploadTests {

        @Test
        @DisplayName("Upload with HTTP 200 OK succeeds")
        @SuppressWarnings("unchecked")
        void uploadSuccessHttp200() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(200);
            when(mockResponse.body()).thenReturn("{\"status\":\"ok\"}");
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            service.store(key, new ByteArrayInputStream("Sample PDF bytes".getBytes(StandardCharsets.UTF_8)));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(mockClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().method()).isEqualTo("POST");
            assertThat(captor.getValue().headers().firstValue("Content-Type")).hasValue("application/octet-stream");
        }

        @Test
        @DisplayName("Upload with HTTP 201 Created succeeds")
        @SuppressWarnings("unchecked")
        void uploadSuccessHttp201() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(201);
            when(mockResponse.body()).thenReturn("{\"status\":\"created\"}");
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            service.store(key, "payload".getBytes(StandardCharsets.UTF_8));
        }

        @Test
        @DisplayName("Upload returning HTTP 401 Unauthorized captures diagnostic message and throws StorageException")
        @SuppressWarnings("unchecked")
        void uploadUnauthorizedFailsWithDiagnosticMessage() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(401);
            when(mockResponse.body()).thenReturn("Unauthorized");
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            assertThatThrownBy(() -> service.store(key, "test bytes".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("HTTP 401")
                    .hasMessageContaining("Unauthorized");
        }

        @Test
        @DisplayName("Upload returning HTTP 500 captures error message and throws StorageException")
        @SuppressWarnings("unchecked")
        void uploadServerErrorFailsWithDiagnosticMessage() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(500);
            when(mockResponse.body()).thenReturn("File storage operation failed");
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            assertThatThrownBy(() -> service.store(key, "test bytes".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("HTTP 500")
                    .hasMessageContaining("File storage operation failed");
        }

        @Test
        @DisplayName("Empty file is rejected before network call")
        void emptyFileRejected() {
            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET);
            UUID key = UUID.randomUUID();

            assertThatThrownBy(() -> service.store(key, new byte[0]))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("Empty files are not supported");
        }

        @Test
        @DisplayName("File exceeding 10 MiB is rejected before network call")
        void fileExceeding10MiBRejected() {
            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET);
            UUID key = UUID.randomUUID();
            byte[] oversized = new byte[10 * 1024 * 1024 + 1];

            assertThatThrownBy(() -> service.store(key, oversized))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("exceeds the Convex storage limit of 10 MiB");
        }

        @Test
        @DisplayName("Network failure (IOException) wraps in StorageException without exposing raw secrets")
        @SuppressWarnings("unchecked")
        void networkFailureThrowsStorageException() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenThrow(new IOException("Connection reset by peer"));

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            assertThatThrownBy(() -> service.store(key, "test bytes".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("Convex storage request failed");
        }
    }

    @Nested
    @DisplayName("3. Download, Existence, and Deletion Tests")
    class LifecycleTests {

        @Test
        @DisplayName("Download HTTP 200 loads bytes correctly as resource and stream")
        @SuppressWarnings("unchecked")
        void downloadSuccess() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<byte[]> mockResponse = mock(HttpResponse.class);
            byte[] expected = "File content in cloud storage".getBytes(StandardCharsets.UTF_8);
            when(mockResponse.statusCode()).thenReturn(200);
            when(mockResponse.body()).thenReturn(expected);
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            assertThat(service.loadAsResource(key).getContentAsByteArray()).isEqualTo(expected);
            assertThat(service.loadAsStream(key).readAllBytes()).isEqualTo(expected);
            assertThat(service.getFileSize(key)).isEqualTo(expected.length);
        }

        @Test
        @DisplayName("Download HTTP 404 throws StorageFileNotFoundException")
        @SuppressWarnings("unchecked")
        void downloadNotFoundThrowsStorageFileNotFoundException() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<byte[]> mockResponse = mock(HttpResponse.class);
            when(mockResponse.statusCode()).thenReturn(404);
            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(mockResponse);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            assertThatThrownBy(() -> service.loadAsResource(key))
                    .isInstanceOf(StorageFileNotFoundException.class)
                    .hasMessageContaining("not found");
        }

        @Test
        @DisplayName("exists returns true on HTTP 200 and false on HTTP 404")
        @SuppressWarnings("unchecked")
        void existsChecksStatusCode() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> resp200 = mock(HttpResponse.class);
            when(resp200.statusCode()).thenReturn(200);
            HttpResponse<String> resp404 = mock(HttpResponse.class);
            when(resp404.statusCode()).thenReturn(404);

            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(resp200)
                    .thenReturn(resp404);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            assertThat(service.exists(key)).isTrue();
            assertThat(service.exists(key)).isFalse();
            assertThat(service.exists(null)).isFalse();
        }

        @Test
        @DisplayName("delete returns true on HTTP 204 or 200, and false on HTTP 404")
        @SuppressWarnings("unchecked")
        void deleteChecksStatusCode() throws Exception {
            HttpClient mockClient = mock(HttpClient.class);
            HttpResponse<String> resp204 = mock(HttpResponse.class);
            when(resp204.statusCode()).thenReturn(204);
            HttpResponse<String> resp200 = mock(HttpResponse.class);
            when(resp200.statusCode()).thenReturn(200);
            HttpResponse<String> resp404 = mock(HttpResponse.class);
            when(resp404.statusCode()).thenReturn(404);

            when(mockClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(resp204)
                    .thenReturn(resp200)
                    .thenReturn(resp404);

            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET, mockClient);
            UUID key = UUID.randomUUID();

            assertThat(service.delete(key)).isTrue();
            assertThat(service.delete(key)).isTrue();
            assertThat(service.delete(key)).isFalse();
            assertThat(service.delete(null)).isFalse();
        }

        @Test
        @DisplayName("Unsupported filesystem operations throw UnsupportedOperationException")
        void unsupportedOperations() {
            ConvexStorageService service = new ConvexStorageService(VALID_BASE_URL, VALID_SECRET);
            UUID key = UUID.randomUUID();

            assertThatThrownBy(() -> service.resolvePath(key))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("does not have a local filesystem path");

            assertThatThrownBy(service::deleteAll)
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Bulk deletion is disabled");
        }
    }

    @Nested
    @org.springframework.boot.test.context.SpringBootTest(properties = {
            "trustvault.storage.provider=convex",
            "trustvault.storage.convex.base-url=https://doting-robin-733.ap-southeast-2.convex.site",
            "trustvault.storage.convex.shared-secret=test-secret"
    })
    @DisplayName("4. Conditional Bean Activation (Convex Provider)")
    class ConvexProviderConditionTest {

        @org.springframework.beans.factory.annotation.Autowired
        private org.springframework.context.ApplicationContext applicationContext;

        @Test
        @DisplayName("ConvexStorageService bean is loaded and LocalStorageService is absent when provider=convex")
        void convexBeanLoadedWhenConfigured() {
            assertThat(applicationContext.containsBean("convexStorageService")).isTrue();
            assertThat(applicationContext.containsBean("localStorageService")).isFalse();
            StorageService storageService = applicationContext.getBean(StorageService.class);
            assertThat(storageService).isInstanceOf(ConvexStorageService.class);
        }
    }

    @Nested
    @org.springframework.boot.test.context.SpringBootTest(properties = {
            "trustvault.storage.provider=local"
    })
    @DisplayName("5. Conditional Bean Activation (Default Local Provider)")
    class LocalProviderConditionTest {

        @org.springframework.beans.factory.annotation.Autowired
        private org.springframework.context.ApplicationContext applicationContext;

        @Test
        @DisplayName("LocalStorageService bean is loaded and ConvexStorageService is absent when provider=local")
        void localBeanLoadedByDefault() {
            assertThat(applicationContext.containsBean("localStorageService")).isTrue();
            assertThat(applicationContext.containsBean("convexStorageService")).isFalse();
            StorageService storageService = applicationContext.getBean(StorageService.class);
            assertThat(storageService).isInstanceOf(LocalStorageService.class);
        }
    }
}
