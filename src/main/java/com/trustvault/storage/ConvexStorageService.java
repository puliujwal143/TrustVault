package com.trustvault.storage;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Convex cloud storage implementation of {@link StorageService}.
 * Communicates with deployed Convex HTTP Actions via HTTPS.
 *
 * <p>Security & Integration Guarantees:
 * <ul>
 *   <li>Communicates exclusively over secure HTTPS endpoints with Bearer token authentication.</li>
 *   <li>Sanitizes diagnostic logging to prevent secret or credential leakage.</li>
 *   <li>Enforces client-side 10 MiB payload limits and rejects empty files.</li>
 *   <li>Supports standard HTTP redirect handling and URL normalization (preventing duplicated routes).</li>
 * </ul>
 */
@Service
@ConditionalOnProperty(name = "trustvault.storage.provider", havingValue = "convex")
public class ConvexStorageService implements StorageService {

    private static final Logger log = LoggerFactory.getLogger(ConvexStorageService.class);

    private static final int MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Pattern matching recognizable accidental shell assignment or variable expression text
     * (e.g. '$env:TRUSTVAULT_CONVEX_SHARED_SECRET = Get-Clipboard', 'Get-Clipboard', '$secret = ...').
     * Does NOT reject legitimate secrets containing '=' (such as standard Base64 padding).
     */
    private static final Pattern ACCIDENTAL_SHELL_EXPRESSION = Pattern.compile(
            "^\\s*\\$env:[A-Za-z0-9_]+(\\s*=.*)?$|" +
            "^\\s*\\$[A-Za-z0-9_]+\\s*=.*|" +
            ".*\\bGet-Clipboard\\b.*|" +
            "^\\s*export\\s+[A-Za-z0-9_]+\\s*=.*|" +
            "^\\s*set\\s+[A-Za-z0-9_]+\\s*=.*",
            Pattern.CASE_INSENSITIVE
    );

    private final String baseUrl;
    private final String sharedSecret;
    private final HttpClient httpClient;

    @Autowired
    public ConvexStorageService(
            @Value("${trustvault.storage.convex.base-url:}") String baseUrl,
            @Value("${trustvault.storage.convex.shared-secret:}") String sharedSecret) {
        this(baseUrl, sharedSecret, null);
    }

    public ConvexStorageService(
            String baseUrl,
            String sharedSecret,
            HttpClient httpClient) {

        String rawUrl = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        // Defensive normalization: remove redundant trailing /files if accidentally configured
        if (rawUrl.endsWith("/files")) {
            rawUrl = rawUrl.substring(0, rawUrl.length() - "/files".length()).replaceAll("/+$", "");
        }
        this.baseUrl = rawUrl;

        String secret = sharedSecret == null ? "" : sharedSecret.trim();
        // Strip accidental surrounding single or double quotes from shell / env files
        if ((secret.startsWith("\"") && secret.endsWith("\"")) || (secret.startsWith("'") && secret.endsWith("'"))) {
            if (secret.length() >= 2) {
                secret = secret.substring(1, secret.length() - 1).trim();
            }
        }
        // Strip accidental "Bearer " prefix if user included it in the environment variable
        if (secret.regionMatches(true, 0, "Bearer ", 0, 7)) {
            secret = secret.substring(7).trim();
        }
        this.sharedSecret = secret;

        if (httpClient != null) {
            this.httpClient = httpClient;
        } else {
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
        }
    }

    @PostConstruct
    @Override
    public void init() {
        if (baseUrl.isBlank() || sharedSecret.isBlank()) {
            throw new StorageException(
                    "Convex storage requires TRUSTVAULT_CONVEX_BASE_URL and "
                            + "TRUSTVAULT_CONVEX_SHARED_SECRET to be configured.");
        }

        // Guard against clearly recognizable accidental PowerShell or shell assignment/expression text
        if (ACCIDENTAL_SHELL_EXPRESSION.matcher(sharedSecret).matches()) {
            throw new StorageException(
                    "TRUSTVAULT_CONVEX_SHARED_SECRET appears to contain a shell variable expression or assignment "
                            + "rather than the secret value itself.");
        }

        URI uri;
        try {
            uri = URI.create(baseUrl);
        } catch (IllegalArgumentException e) {
            throw new StorageException("Convex storage URL is not a valid URI.", e);
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || uri.getUserInfo() != null
                || uri.getQuery() != null
                || uri.getFragment() != null) {
            throw new StorageException(
                    "Convex storage URL must be a valid HTTPS base URL.");
        }

        // Safe diagnostic connectivity check on startup
        checkConnectivity();
    }

    /**
     * Non-blocking diagnostic connectivity check against Convex /health endpoint.
     * Logs actionable diagnostics without exposing credentials. Does not throw
     * exceptions to permit offline testing and graceful startup.
     */
    void checkConnectivity() {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/health"))
                    .timeout(Duration.ofSeconds(5))
                    .header("Authorization", "Bearer " + sharedSecret)
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            int status = response.statusCode();
            if (status == 200) {
                log.info("Convex storage connectivity and authentication verified successfully (HTTP 200).");
            } else if (status == 401) {
                log.error("Convex storage connectivity check FAILED (HTTP 401 Unauthorized): "
                        + "The configured TRUSTVAULT_CONVEX_SHARED_SECRET does not match the Convex deployment.");
            } else if (status == 503) {
                log.error("Convex storage connectivity check FAILED (HTTP 503 Service Unavailable): "
                        + "The Convex deployment is missing the TRUSTVAULT_SHARED_SECRET configuration.");
            } else {
                log.warn("Convex storage connectivity check returned HTTP status {}: {}",
                        status, extractSanitizedResponseBody(response));
            }
        } catch (Exception e) {
            log.debug("Convex storage connectivity check could not complete during startup (offline/mocked): {}", e.getMessage());
        }
    }

    @Override
    public void store(UUID storageKey, InputStream inputStream) {
        Objects.requireNonNull(storageKey, "storageKey must not be null");
        Objects.requireNonNull(inputStream, "inputStream must not be null");

        byte[] content;
        try (InputStream input = inputStream;
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int total = 0;
            int read;

            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > MAX_FILE_SIZE_BYTES) {
                    throw new StorageException(
                            "File exceeds the Convex storage limit of 10 MiB.");
                }
                output.write(buffer, 0, read);
            }

            content = output.toByteArray();
        } catch (StorageException e) {
            throw e;
        } catch (IOException e) {
            throw new StorageException("Failed to read upload stream.", e);
        }

        store(storageKey, content);
    }

    @Override
    public void store(UUID storageKey, byte[] content) {
        Objects.requireNonNull(storageKey, "storageKey must not be null");
        Objects.requireNonNull(content, "content must not be null");

        if (content.length == 0) {
            throw new StorageException("Empty files are not supported by Convex storage.");
        }
        if (content.length > MAX_FILE_SIZE_BYTES) {
            throw new StorageException("File exceeds the Convex storage limit of 10 MiB.");
        }

        ensureConfigured();

        URI targetUri = fileUri(storageKey);
        log.info("Sending Convex storage upload request: method=POST, url={}, payloadBytes={}",
                targetUri, content.length);

        HttpRequest request = HttpRequest.newBuilder(targetUri)
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + sharedSecret)
                .header("Content-Type", "application/octet-stream")
                .POST(HttpRequest.BodyPublishers.ofByteArray(content))
                .build();

        HttpResponse<String> response = send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

        int status = response.statusCode();
        String sanitizedBody = extractSanitizedResponseBody(response);
        log.info("Received Convex storage upload response: status={}, body='{}'", status, sanitizedBody);

        // Accept 200 OK and 201 Created as valid upload success responses
        if (status < 200 || status >= 300) {
            throw httpFailure("upload", status, sanitizedBody);
        }
    }

    @Override
    public Resource loadAsResource(UUID storageKey) {
        byte[] content = download(storageKey);
        return new ByteArrayResource(content) {
            @Override
            public String getFilename() {
                return storageKey + ".bin";
            }
        };
    }

    @Override
    public InputStream loadAsStream(UUID storageKey) {
        return new ByteArrayInputStream(download(storageKey));
    }

    @Override
    public boolean exists(UUID storageKey) {
        if (storageKey == null) {
            return false;
        }

        ensureConfigured();

        URI targetUri = fileUri(storageKey);
        log.debug("Sending Convex storage existence check: method=GET, url={}", targetUri);

        HttpRequest request = HttpRequest.newBuilder(targetUri)
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + sharedSecret)
                .GET()
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            int status = response.statusCode();
            log.debug("Received Convex storage existence response: status={}", status);
            if (status == 200) {
                return true;
            }
            if (status == 404) {
                return false;
            }
            String sanitizedBody = extractSanitizedResponseBody(response);
            throw httpFailure("check file existence", status, sanitizedBody);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StorageException("File existence check was interrupted.", e);
        } catch (IOException e) {
            throw new StorageException("File existence check failed.", e);
        }
    }

    @Override
    public long getFileSize(UUID storageKey) {
        return download(storageKey).length;
    }

    @Override
    public boolean delete(UUID storageKey) {
        if (storageKey == null) {
            return false;
        }

        ensureConfigured();

        URI targetUri = fileUri(storageKey);
        log.info("Sending Convex storage delete request: method=DELETE, url={}", targetUri);

        HttpRequest request = HttpRequest.newBuilder(targetUri)
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + sharedSecret)
                .DELETE()
                .build();

        HttpResponse<String> response = send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

        int status = response.statusCode();
        log.info("Received Convex storage delete response: status={}", status);
        if (status == 204 || status == 200) {
            return true;
        }
        if (status == 404) {
            return false;
        }
        String sanitizedBody = extractSanitizedResponseBody(response);
        throw httpFailure("delete", status, sanitizedBody);
    }

    @Override
    public Path resolvePath(UUID storageKey) {
        throw new UnsupportedOperationException(
                "Convex cloud storage does not have a local filesystem path.");
    }

    @Override
    public void deleteAll() {
        throw new UnsupportedOperationException(
                "Bulk deletion is disabled for Convex storage.");
    }

    private byte[] download(UUID storageKey) {
        Objects.requireNonNull(storageKey, "storageKey must not be null");
        ensureConfigured();

        URI targetUri = fileUri(storageKey);
        log.info("Sending Convex storage download request: method=GET, url={}", targetUri);

        HttpRequest request = HttpRequest.newBuilder(targetUri)
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + sharedSecret)
                .GET()
                .build();

        HttpResponse<byte[]> response = send(request, HttpResponse.BodyHandlers.ofByteArray());

        int status = response.statusCode();
        log.info("Received Convex storage download response: status={}, payloadBytes={}",
                status, response.body() != null ? response.body().length : 0);
        if (status == 404) {
            throw new StorageFileNotFoundException(
                    "The requested file was not found in Convex storage.");
        }
        if (status != 200) {
            String sanitizedBody = extractSanitizedResponseBody(response);
            throw httpFailure("download", status, sanitizedBody);
        }
        if (response.body().length > MAX_FILE_SIZE_BYTES) {
            throw new StorageException("Downloaded file exceeds the 10 MiB storage limit.");
        }

        return response.body();
    }

    private URI fileUri(UUID storageKey) {
        String encodedKey = URLEncoder.encode(
                storageKey.toString(), StandardCharsets.UTF_8);
        return URI.create(baseUrl + "/files?storageKey=" + encodedKey);
    }

    private void ensureConfigured() {
        if (baseUrl.isBlank() || sharedSecret.isBlank()) {
            throw new StorageException("Convex storage is not configured.");
        }
    }

    private <T> HttpResponse<T> send(
            HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) {
        try {
            return httpClient.send(request, bodyHandler);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StorageException("Convex storage request was interrupted.", e);
        } catch (IOException e) {
            throw new StorageException("Convex storage request failed.", e);
        }
    }

    private StorageException httpFailure(String operation, int status, String responseBody) {
        String detail = (responseBody == null || responseBody.isBlank()) ? "" : " - " + responseBody;
        log.warn("Convex storage {} failed with HTTP status {}{}", operation, status, detail);
        return new StorageException(
                "Convex storage " + operation + " failed (HTTP " + status + ")" + detail + ".");
    }

    private String extractSanitizedResponseBody(HttpResponse<?> response) {
        if (response == null || response.body() == null) {
            return "";
        }
        String body;
        if (response.body() instanceof byte[] bytes) {
            body = new String(bytes, StandardCharsets.UTF_8);
        } else {
            body = response.body().toString();
        }

        if (body.isBlank()) {
            return "";
        }

        // Redact shared secret if reflected in response
        if (!sharedSecret.isBlank()) {
            body = body.replace(sharedSecret, "********");
        }

        // Strip carriage returns and newlines to prevent log injection, and truncate length
        String sanitized = body.replaceAll("[\r\n\t]", " ").trim();
        if (sanitized.length() > 256) {
            sanitized = sanitized.substring(0, 256) + "...";
        }
        return sanitized;
    }
}
