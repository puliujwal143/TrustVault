package com.trustvault.storage;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit and integration tests for LocalStorageService.
 *
 * Verifies:
 * - Storing and loading files via Resource and InputStream.
 * - Atomic file replacement.
 * - Existence checking and accurate file sizing.
 * - Exception behavior on missing files and invalid arguments.
 * - Safe file deletion.
 * - Path traversal containment and static directory rejection.
 * - Cleanup of temporary staging files when stream writes fail.
 * - Spring Boot context wiring with configured upload-dir.
 */
@SpringBootTest
class LocalStorageServiceTest {

    @Autowired
    private LocalStorageService springLocalStorageService;

    @TempDir
    private Path tempStorageDir;

    private LocalStorageService storageService;

    @BeforeEach
    void setUp() {
        storageService = new LocalStorageService(tempStorageDir);
    }

    @AfterEach
    void tearDown() {
        storageService.deleteAll();
    }

    @Test
    @DisplayName("store and loadAsResource: should successfully persist and retrieve file content")
    void storeAndLoadAsResource_shouldSucceed() throws IOException {
        UUID key = UUID.randomUUID();
        byte[] content = "Confidential TrustVault Document Content".getBytes(StandardCharsets.UTF_8);

        storageService.store(key, content);

        assertThat(storageService.exists(key)).isTrue();
        Resource resource = storageService.loadAsResource(key);
        assertThat(resource.exists()).isTrue();
        assertThat(resource.isReadable()).isTrue();
        assertThat(resource.getContentAsByteArray()).isEqualTo(content);
    }

    @Test
    @DisplayName("store and loadAsStream: should successfully read stored file as stream")
    void storeAndLoadAsStream_shouldSucceed() throws IOException {
        UUID key = UUID.randomUUID();
        byte[] content = "Binary Stream Data payload".getBytes(StandardCharsets.UTF_8);

        storageService.store(key, new ByteArrayInputStream(content));

        try (InputStream stream = storageService.loadAsStream(key)) {
            byte[] readBytes = stream.readAllBytes();
            assertThat(readBytes).isEqualTo(content);
        }
    }

    @Test
    @DisplayName("store: should atomically overwrite existing file when key is reused")
    void store_shouldOverwriteExistingFileAtomically() throws IOException {
        UUID key = UUID.randomUUID();
        byte[] v1 = "Version 1 Content".getBytes(StandardCharsets.UTF_8);
        byte[] v2 = "Version 2 Content - Updated and Hardened".getBytes(StandardCharsets.UTF_8);

        storageService.store(key, v1);
        assertThat(storageService.loadAsResource(key).getContentAsByteArray()).isEqualTo(v1);

        storageService.store(key, v2);
        assertThat(storageService.loadAsResource(key).getContentAsByteArray()).isEqualTo(v2);
    }

    @Test
    @DisplayName("exists: should return true for stored file and false for missing file")
    void exists_shouldAccuratelyReflectFilePresence() {
        UUID key = UUID.randomUUID();

        assertThat(storageService.exists(key)).isFalse();
        assertThat(storageService.exists(null)).isFalse();

        storageService.store(key, "Sample".getBytes(StandardCharsets.UTF_8));
        assertThat(storageService.exists(key)).isTrue();

        storageService.delete(key);
        assertThat(storageService.exists(key)).isFalse();
    }

    @Test
    @DisplayName("getFileSize: should return exact byte count of stored file")
    void getFileSize_shouldReturnExactByteCount() {
        UUID key = UUID.randomUUID();
        byte[] content = new byte[2048];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) (i % 128);
        }

        storageService.store(key, content);
        assertThat(storageService.getFileSize(key)).isEqualTo(2048L);
    }

    @Test
    @DisplayName("getFileSize: should throw StorageFileNotFoundException when key does not exist")
    void getFileSize_shouldThrowExceptionForMissingKey() {
        UUID missingKey = UUID.randomUUID();
        assertThatThrownBy(() -> storageService.getFileSize(missingKey))
                .isInstanceOf(StorageFileNotFoundException.class)
                .hasMessageContaining(missingKey.toString());
    }

    @Test
    @DisplayName("loadAsResource: should throw StorageFileNotFoundException for missing file")
    void loadAsResource_shouldThrowExceptionForMissingFile() {
        UUID missingKey = UUID.randomUUID();
        assertThatThrownBy(() -> storageService.loadAsResource(missingKey))
                .isInstanceOf(StorageFileNotFoundException.class)
                .hasMessageContaining(missingKey.toString());
    }

    @Test
    @DisplayName("loadAsStream: should throw StorageFileNotFoundException for missing file")
    void loadAsStream_shouldThrowExceptionForMissingFile() {
        UUID missingKey = UUID.randomUUID();
        assertThatThrownBy(() -> storageService.loadAsStream(missingKey))
                .isInstanceOf(StorageFileNotFoundException.class)
                .hasMessageContaining(missingKey.toString());
    }

    @Test
    @DisplayName("delete: should delete existing file and return true; false for missing file")
    void delete_shouldBehaveCorrectly() {
        UUID key = UUID.randomUUID();
        storageService.store(key, "Temporary".getBytes(StandardCharsets.UTF_8));

        assertThat(storageService.delete(key)).isTrue();
        assertThat(storageService.exists(key)).isFalse();

        // Second deletion returns false because file is already removed
        assertThat(storageService.delete(key)).isFalse();
        assertThat(storageService.delete(null)).isFalse();
    }

    @Test
    @DisplayName("store: should reject null key or null content with StorageException")
    void store_shouldRejectNullArguments() {
        UUID key = UUID.randomUUID();
        byte[] content = "Data".getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> storageService.store(null, content))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("Storage key must not be null");

        assertThatThrownBy(() -> storageService.store(key, (byte[]) null))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("File content must not be null");

        assertThatThrownBy(() -> storageService.store(key, (InputStream) null))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("Input stream must not be null");
    }

    @Test
    @DisplayName("store: when stream fails mid-read, temporary staging file must be cleaned up")
    void store_whenStreamFails_shouldCleanUpTempFile() throws IOException {
        UUID key = UUID.randomUUID();

        // Faulty InputStream that fails after reading 10 bytes
        InputStream faultyStream = new InputStream() {
            private int count = 0;
            @Override
            public int read() throws IOException {
                if (++count > 10) {
                    throw new IOException("Simulated network/disk disconnect during streaming");
                }
                return 42;
            }
        };

        assertThatThrownBy(() -> storageService.store(key, faultyStream))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("Failed to store file");

        // Target file should not have been created
        assertThat(storageService.exists(key)).isFalse();

        // Verify no leftover .tmp files exist in the storage directory
        try (Stream<Path> files = Files.list(tempStorageDir)) {
            long tempFileCount = files.filter(p -> p.getFileName().toString().endsWith(LocalStorageService.TEMP_EXTENSION)).count();
            assertThat(tempFileCount).isZero();
        }
    }

    @Test
    @DisplayName("resolvePath: strictly validates parent containment and UUID naming")
    void resolvePath_shouldValidateContainment() {
        UUID key = UUID.randomUUID();
        Path resolved = storageService.resolvePath(key);

        assertThat(resolved).isNotNull();
        assertThat(resolved.getParent()).isEqualTo(tempStorageDir.toAbsolutePath().normalize());
        assertThat(resolved.getFileName().toString()).isEqualTo(key + LocalStorageService.FILE_EXTENSION);

        assertThatThrownBy(() -> storageService.resolvePath(null))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("Storage key must not be null");
    }

    @Test
    @DisplayName("security: rejects storage directory configuration inside public or static resource folders")
    void security_shouldRejectStaticWebDirectories() {
        Path invalidStaticPath = Paths.get("./src/main/resources/static/uploads");
        assertThatThrownBy(() -> new LocalStorageService(invalidStaticPath))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("Security violation");
    }

    @Test
    @DisplayName("springContext: Spring Boot autowires LocalStorageService with configured upload-dir")
    void springContext_shouldAutowireLocalStorageService() {
        assertThat(springLocalStorageService).isNotNull();
        assertThat(springLocalStorageService.getRootLocation()).isNotNull();
        // Configured in test application.properties as ./target/test-storage
        assertThat(springLocalStorageService.getRootLocation().toString().replace('\\', '/'))
                .contains("target/test-storage");
    }

    @Test
    @DisplayName("init: should reject filesystem root paths like / and root drive")
    void init_shouldRejectFilesystemRootPaths() {
        assertThatThrownBy(() -> new LocalStorageService(Paths.get("/")))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("cannot be a filesystem root");

        for (Path root : java.nio.file.FileSystems.getDefault().getRootDirectories()) {
            assertThatThrownBy(() -> new LocalStorageService(root))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("cannot be a filesystem root");
        }
    }

    @Test
    @DisplayName("init: should preserve valid temporary and relative storage directories")
    void init_shouldPreserveValidStorageDirectories() {
        Path validNestedDir = tempStorageDir.resolve("valid-sub-dir");
        LocalStorageService validService = new LocalStorageService(validNestedDir);
        assertThat(validService.getRootLocation()).isEqualTo(validNestedDir.toAbsolutePath().normalize());
        assertThat(Files.isDirectory(validNestedDir)).isTrue();
    }

    @Test
    @DisplayName("init: should clean up only abandoned tv_upload_*.tmp staging files, preserving .bin and unrelated .tmp files")
    void init_shouldCleanUpOnlyApplicationStagingFiles() throws IOException {
        Path abandonedStaging1 = tempStorageDir.resolve("tv_upload_" + UUID.randomUUID() + "_staging1.tmp");
        Path abandonedStaging2 = tempStorageDir.resolve("tv_upload_" + UUID.randomUUID() + "_staging2.tmp");
        Path persistentBin = tempStorageDir.resolve(UUID.randomUUID() + ".bin");
        Path unrelatedTmp = tempStorageDir.resolve("unrelated_backup.tmp");
        Path unrelatedTxt = tempStorageDir.resolve("notes.txt");

        Files.writeString(abandonedStaging1, "abandoned 1");
        Files.writeString(abandonedStaging2, "abandoned 2");
        Files.writeString(persistentBin, "important document binary");
        Files.writeString(unrelatedTmp, "system or unrelated temp data");
        Files.writeString(unrelatedTxt, "text note");

        // Re-initialize a new LocalStorageService on this directory
        new LocalStorageService(tempStorageDir);

        // Staging files matching tv_upload_*.tmp must be deleted
        assertThat(Files.exists(abandonedStaging1)).isFalse();
        assertThat(Files.exists(abandonedStaging2)).isFalse();

        // Persistent .bin and other files must be preserved
        assertThat(Files.exists(persistentBin)).isTrue();
        assertThat(Files.exists(unrelatedTmp)).isTrue();
        assertThat(Files.exists(unrelatedTxt)).isTrue();
    }

    @Test
    @DisplayName("symlink: exists() should return false when storage file is a planted symbolic link")
    void symlink_exists_shouldReturnFalseForPlantedSymlink() throws IOException {
        Path externalTarget = Files.createTempFile("external-target-", ".txt");
        try {
            UUID key = UUID.randomUUID();
            Path symlinkPath = tempStorageDir.resolve(key + LocalStorageService.FILE_EXTENSION);
            boolean created = tryCreateSymbolicLink(symlinkPath, externalTarget);
            org.junit.jupiter.api.Assumptions.assumeTrue(created, "Symbolic link creation not supported or permitted on this OS/user environment");

            assertThat(storageService.exists(key)).isFalse();
        } finally {
            Files.deleteIfExists(externalTarget);
        }
    }

    @Test
    @DisplayName("symlink: loadAsResource() should reject planted symbolic links")
    void symlink_loadAsResource_shouldRejectPlantedSymlink() throws IOException {
        Path externalTarget = Files.createTempFile("external-target-", ".txt");
        try {
            UUID key = UUID.randomUUID();
            Path symlinkPath = tempStorageDir.resolve(key + LocalStorageService.FILE_EXTENSION);
            boolean created = tryCreateSymbolicLink(symlinkPath, externalTarget);
            org.junit.jupiter.api.Assumptions.assumeTrue(created, "Symbolic link creation not supported or permitted on this OS/user environment");

            assertThatThrownBy(() -> storageService.loadAsResource(key))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("Symbolic links are strictly prohibited");
        } finally {
            Files.deleteIfExists(externalTarget);
        }
    }

    @Test
    @DisplayName("symlink: loadAsStream() should reject planted symbolic links")
    void symlink_loadAsStream_shouldRejectPlantedSymlink() throws IOException {
        Path externalTarget = Files.createTempFile("external-target-", ".txt");
        try {
            UUID key = UUID.randomUUID();
            Path symlinkPath = tempStorageDir.resolve(key + LocalStorageService.FILE_EXTENSION);
            boolean created = tryCreateSymbolicLink(symlinkPath, externalTarget);
            org.junit.jupiter.api.Assumptions.assumeTrue(created, "Symbolic link creation not supported or permitted on this OS/user environment");

            assertThatThrownBy(() -> storageService.loadAsStream(key))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("Symbolic links are strictly prohibited");
        } finally {
            Files.deleteIfExists(externalTarget);
        }
    }

    @Test
    @DisplayName("symlink: getFileSize() should reject planted symbolic links")
    void symlink_getFileSize_shouldRejectPlantedSymlink() throws IOException {
        Path externalTarget = Files.createTempFile("external-target-", ".txt");
        try {
            UUID key = UUID.randomUUID();
            Path symlinkPath = tempStorageDir.resolve(key + LocalStorageService.FILE_EXTENSION);
            boolean created = tryCreateSymbolicLink(symlinkPath, externalTarget);
            org.junit.jupiter.api.Assumptions.assumeTrue(created, "Symbolic link creation not supported or permitted on this OS/user environment");

            assertThatThrownBy(() -> storageService.getFileSize(key))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("Symbolic links are strictly prohibited");
        } finally {
            Files.deleteIfExists(externalTarget);
        }
    }

    @Test
    @DisplayName("symlink: delete() should reject planted symbolic links without following them")
    void symlink_delete_shouldRejectPlantedSymlink() throws IOException {
        Path externalTarget = Files.createTempFile("external-target-", ".txt");
        try {
            UUID key = UUID.randomUUID();
            Path symlinkPath = tempStorageDir.resolve(key + LocalStorageService.FILE_EXTENSION);
            boolean created = tryCreateSymbolicLink(symlinkPath, externalTarget);
            org.junit.jupiter.api.Assumptions.assumeTrue(created, "Symbolic link creation not supported or permitted on this OS/user environment");

            assertThatThrownBy(() -> storageService.delete(key))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("Symbolic links are strictly prohibited");

            // Verify the external target was NOT touched or deleted
            assertThat(Files.exists(externalTarget)).isTrue();
        } finally {
            Files.deleteIfExists(externalTarget);
        }
    }

    @Test
    @DisplayName("symlink: store() should reject overwriting a planted symbolic link")
    void symlink_store_shouldRejectPlantedSymlink() throws IOException {
        Path externalTarget = Files.createTempFile("external-target-", ".txt");
        try {
            UUID key = UUID.randomUUID();
            Path symlinkPath = tempStorageDir.resolve(key + LocalStorageService.FILE_EXTENSION);
            boolean created = tryCreateSymbolicLink(symlinkPath, externalTarget);
            org.junit.jupiter.api.Assumptions.assumeTrue(created, "Symbolic link creation not supported or permitted on this OS/user environment");

            assertThatThrownBy(() -> storageService.store(key, "malicious overwrite".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(StorageException.class)
                    .hasMessageContaining("Symbolic links are strictly prohibited");
        } finally {
            Files.deleteIfExists(externalTarget);
        }
    }

    private boolean tryCreateSymbolicLink(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
            return true;
        } catch (UnsupportedOperationException | SecurityException | IOException e) {
            return false;
        }
    }
}
