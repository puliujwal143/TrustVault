package com.trustvault.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Local filesystem implementation of {@link StorageService}.
 *
 * <p>
 * Security & Isolation Architecture:
 * <ul>
 * <li><b>Private Storage Root</b>: Stores files in a configurable directory
 * (default: {@code ./private-storage/uploads}),
 * strictly isolated from web server static resources (e.g. {@code /static/},
 * {@code /public/}).</li>
 * <li><b>Storage Root Safety</b>: Rejects filesystem roots (e.g. {@code /} or
 * {@code C:\}) to prevent catastrophic
 * misconfiguration or root traversal.</li>
 * <li><b>Identifier Obfuscation</b>: Files are named on disk using immutable
 * {@link UUID}s (e.g. {@code {storageKey}.bin}).
 * User-supplied or client-controlled filenames are <em>never</em> used to
 * construct disk paths.</li>
 * <li><b>Path Traversal Defense</b>: Strict canonicalization and
 * parent-containment checks guarantee that
 * resolved paths never escape the configured storage directory.</li>
 * <li><b>Symbolic Link Defense</b>: Rejects symbolic links for existing storage
 * files across all operations
 * ({@code loadAsStream}, {@code loadAsResource}, {@code exists},
 * {@code getFileSize}, {@code delete}, {@code store})
 * using {@link LinkOption#NOFOLLOW_LINKS} and explicit checks to defend against
 * planted symlink attacks.
 * (Note: While Java NIO defenses mitigate symlink escapes, absolute immunity
 * against all local filesystem
 * TOCTOU races remains bounded by host operating system kernel and filesystem
 * semantics).</li>
 * <li><b>Atomic Replacement & Staging Cleanup</b>: Writes stream into a
 * temporary staging file first and promote to the final
 * destination using an atomic filesystem move ({@code ATOMIC_MOVE}). Any
 * abandoned staging files matching
 * {@code tv_upload_*.tmp} are cleaned up on startup.</li>
 * <li><b>Ephemeral Storage Limitation Note</b>: This local implementation
 * writes to the container/host filesystem.
 * On free cloud hosting platforms with ephemeral disks (such as Render or
 * Railway free tiers), local disk state
 * is reset on redeployment or container restart. Production deployments
 * requiring cross-instance durability
 * should bind a persistent volume or adopt a cloud object storage
 * provider.</li>
 * </ul>
 */
@Service
@ConditionalOnProperty(name = "trustvault.storage.provider", havingValue = "local", matchIfMissing = true)
public class LocalStorageService implements StorageService {

    private static final Logger log = LoggerFactory.getLogger(LocalStorageService.class);

    public static final String FILE_EXTENSION = ".bin";
    public static final String TEMP_PREFIX = "tv_upload_";
    public static final String TEMP_EXTENSION = ".tmp";

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private final Path rootLocation;

    /**
     * Programmatic constructor accepting a direct {@link Path}, useful for hermetic
     * testing.
     *
     * @param rootLocation the target root directory for storage
     */
    public LocalStorageService(Path rootLocation) {
        Objects.requireNonNull(rootLocation, "Root storage location must not be null");
        this.rootLocation = rootLocation.toAbsolutePath().normalize();
        init();
    }

    /**
     * Spring-managed constructor injecting the configured upload directory
     * property.
     *
     * @param uploadDir configured storage path (default:
     *                  {@code ./private-storage/uploads})
     */
    @Autowired
    public LocalStorageService(@Value("${trustvault.storage.upload-dir:./private-storage/uploads}") String uploadDir) {
        Objects.requireNonNull(uploadDir, "Upload directory property must not be null");
        this.rootLocation = Paths.get(uploadDir).toAbsolutePath().normalize();
        init();
    }

    @Override
    public void init() {
        assertStoragePathNotPublic(this.rootLocation);
        assertStoragePathNotRoot(this.rootLocation);

        try {
            if (!Files.exists(this.rootLocation)) {
                Files.createDirectories(this.rootLocation);
                log.info("Initialized TrustVault private storage directory at: {}", this.rootLocation);
            } else if (!Files.isDirectory(this.rootLocation)) {
                throw new StorageException(
                        "Configured storage path exists but is not a directory: " + this.rootLocation);
            }

            if (!Files.isWritable(this.rootLocation)) {
                throw new StorageException("Storage directory is not writable: " + this.rootLocation);
            }

            // Clean up abandoned staging files from prior interrupted runs
            cleanupAbandonedStagingFiles();
        } catch (IOException ex) {
            throw new StorageException("Could not initialize storage directory: " + this.rootLocation, ex);
        }
    }

    @Override
    public void store(UUID storageKey, InputStream inputStream) {
        if (storageKey == null) {
            throw new StorageException("Storage key must not be null");
        }
        if (inputStream == null) {
            throw new StorageException("Input stream must not be null");
        }

        Path targetPath = resolvePath(storageKey);
        assertNotSymbolicLink(targetPath, storageKey);

        Path tempPath = this.rootLocation.resolve(TEMP_PREFIX + storageKey + "_" + UUID.randomUUID() + TEMP_EXTENSION)
                .normalize()
                .toAbsolutePath();

        try {
            // 1. Stream incoming bytes into an isolated temporary staging file
            Files.copy(inputStream, tempPath, StandardCopyOption.REPLACE_EXISTING);

            // 2. Re-verify target is not a symlink before replacement
            assertNotSymbolicLink(targetPath, storageKey);

            // 3. Atomically promote the staged file to the final destination
            try {
                Files.move(tempPath, targetPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                log.debug("Atomic move not supported on current filesystem; falling back to standard replace: {}",
                        ex.getMessage());
                Files.move(tempPath, targetPath, StandardCopyOption.REPLACE_EXISTING);
            }

            log.debug("Successfully stored file for storage key: {}", storageKey);
        } catch (IOException ex) {
            throw new StorageException("Failed to store file for storage key: " + storageKey, ex);
        } finally {
            // Guarantee that temporary staging files are deleted if an error occurred
            // before atomic move
            try {
                Files.deleteIfExists(tempPath);
            } catch (IOException cleanupEx) {
                log.warn("Failed to delete temporary staging file after upload: {}", tempPath, cleanupEx);
            }
        }
    }

    @Override
    public void store(UUID storageKey, byte[] content) {
        if (content == null) {
            throw new StorageException("File content must not be null");
        }
        try (ByteArrayInputStream bais = new ByteArrayInputStream(content)) {
            store(storageKey, bais);
        } catch (IOException ex) {
            throw new StorageException("Failed to store byte content for storage key: " + storageKey, ex);
        }
    }

    @Override
    public Resource loadAsResource(UUID storageKey) {
        Path filePath = resolvePath(storageKey);
        if (!Files.exists(filePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new StorageFileNotFoundException("Could not read file for storage key: " + storageKey);
        }

        assertNotSymbolicLink(filePath, storageKey);

        if (!Files.isRegularFile(filePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new StorageFileNotFoundException("Storage path is not a regular file for key: " + storageKey);
        }

        try {
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists() && resource.isReadable()) {
                return resource;
            } else {
                throw new StorageFileNotFoundException("Could not read file for storage key: " + storageKey);
            }
        } catch (MalformedURLException ex) {
            throw new StorageFileNotFoundException("Malformed URL for storage key: " + storageKey, ex);
        }
    }

    @Override
    public InputStream loadAsStream(UUID storageKey) {
        Path filePath = resolvePath(storageKey);
        if (!Files.exists(filePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new StorageFileNotFoundException("File not found for storage key: " + storageKey);
        }

        assertNotSymbolicLink(filePath, storageKey);

        if (!Files.isRegularFile(filePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new StorageFileNotFoundException("Storage path is not a regular file for key: " + storageKey);
        }

        try {
            return Files.newInputStream(filePath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException ex) {
            throw new StorageException("Could not open input stream for storage key: " + storageKey, ex);
        }
    }

    @Override
    public boolean exists(UUID storageKey) {
        if (storageKey == null) {
            return false;
        }
        try {
            Path filePath = resolvePath(storageKey);
            if (Files.isSymbolicLink(filePath)) {
                log.warn("Symbolic link detected for storage key '{}'; rejecting existence check", storageKey);
                return false;
            }
            return Files.exists(filePath, LinkOption.NOFOLLOW_LINKS)
                    && Files.isRegularFile(filePath, LinkOption.NOFOLLOW_LINKS);
        } catch (StorageException ex) {
            return false;
        }
    }

    @Override
    public long getFileSize(UUID storageKey) {
        Path filePath = resolvePath(storageKey);
        if (!Files.exists(filePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new StorageFileNotFoundException("File not found for storage key: " + storageKey);
        }

        assertNotSymbolicLink(filePath, storageKey);

        if (!Files.isRegularFile(filePath, LinkOption.NOFOLLOW_LINKS)) {
            throw new StorageFileNotFoundException("Storage path is not a regular file for key: " + storageKey);
        }

        try {
            return Files.size(filePath);
        } catch (IOException ex) {
            throw new StorageException("Failed to determine file size for storage key: " + storageKey, ex);
        }
    }

    @Override
    public boolean delete(UUID storageKey) {
        if (storageKey == null) {
            return false;
        }
        Path filePath = resolvePath(storageKey);
        assertNotSymbolicLink(filePath, storageKey);
        try {
            boolean deleted = Files.deleteIfExists(filePath);
            if (deleted) {
                log.debug("Deleted storage file for key: {}", storageKey);
            }
            return deleted;
        } catch (IOException ex) {
            throw new StorageException("Failed to delete file for storage key: " + storageKey, ex);
        }
    }

    @Override
    public Path resolvePath(UUID storageKey) {
        if (storageKey == null) {
            throw new StorageException("Storage key must not be null");
        }

        String keyStr = storageKey.toString();
        if (!UUID_PATTERN.matcher(keyStr).matches()) {
            throw new StorageException("Invalid storage key format: " + keyStr);
        }

        String filename = keyStr + FILE_EXTENSION;
        Path resolved = this.rootLocation.resolve(filename).normalize().toAbsolutePath();

        // Strict parent containment check defending against path traversal
        if (!resolved.getParent().equals(this.rootLocation) || !resolved.startsWith(this.rootLocation)) {
            log.error("Path traversal attempt detected with storage key: {}", keyStr);
            throw new StorageException("Security violation: path traversal attempt for key: " + keyStr);
        }

        return resolved;
    }

    @Override
    public void deleteAll() {
        if (!Files.exists(this.rootLocation)) {
            return;
        }
        try (Stream<Path> stream = Files.walk(this.rootLocation)) {
            stream.filter(path -> !path.equals(this.rootLocation))
                    .sorted((a, b) -> b.compareTo(a)) // Delete children before parents
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ex) {
                            log.warn("Failed to delete path during cleanup: {}", path, ex);
                        }
                    });
            log.debug("Cleaned all files in storage directory: {}", this.rootLocation);
        } catch (IOException ex) {
            throw new StorageException("Failed to clean up storage root directory: " + this.rootLocation, ex);
        }
    }

    /**
     * Asserts that the configured storage path is not located inside public static
     * web resource folders.
     */
    private void assertStoragePathNotPublic(Path path) {
        String normalized = path.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
        if (normalized.contains("/src/main/resources/static")
                || normalized.contains("/src/main/resources/public")
                || normalized.contains("/target/classes/static")
                || normalized.contains("/target/classes/public")) {
            throw new StorageException(
                    "Security violation: Storage directory must not be located within public or static web resource directories: "
                            + path);
        }
    }

    /**
     * Asserts that the configured storage path is not a filesystem root.
     */
    private void assertStoragePathNotRoot(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        if (normalized.getParent() == null || normalized.equals(normalized.getRoot())) {
            throw new StorageException(
                    "Security violation: Configured storage path cannot be a filesystem root: " + path);
        }
    }

    /**
     * Asserts that the given path is not a symbolic link.
     */
    private void assertNotSymbolicLink(Path filePath, UUID storageKey) {
        if (Files.isSymbolicLink(filePath)) {
            log.error("Security violation: Symbolic link detected for storage key: {}", storageKey);
            throw new StorageException("Security violation: Symbolic links are strictly prohibited: " + storageKey);
        }
    }

    /**
     * Cleans up abandoned temporary staging files matching the application pattern
     * tv_upload_*.tmp on startup.
     */
    private void cleanupAbandonedStagingFiles() {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(this.rootLocation, "tv_upload_*.tmp")) {
            for (Path entry : stream) {
                if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(entry)) {
                    try {
                        Files.deleteIfExists(entry);
                        log.info("Cleaned up abandoned temporary staging file on startup: {}", entry.getFileName());
                    } catch (IOException ex) {
                        log.warn("Could not delete abandoned temporary staging file: {}", entry, ex);
                    }
                }
            }
        } catch (IOException ex) {
            log.warn("Failed to enumerate abandoned staging files during startup in: {}", this.rootLocation, ex);
        }
    }

    public Path getRootLocation() {
        return rootLocation;
    }
}
