package com.trustvault.storage;

import org.springframework.core.io.Resource;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Storage service abstraction defining operations for private document file management.
 *
 * <p>Security & Isolation Principles:
 * <ul>
 *   <li>All operations reference files by an opaque, immutable {@link UUID} storage key,
 *       completely decoupling disk paths from client-supplied or user-controlled filenames.</li>
 *   <li>Implementations store files in private storage locations isolated from web server
 *       roots and static asset directories.</li>
 *   <li>Supports atomic file replacement and isolated retrieval through streaming constructs.</li>
 * </ul>
 */
public interface StorageService {

    /**
     * Initializes the storage engine, validating that the underlying target directory
     * exists, is writable, and does not violate security constraints (e.g., static web directory isolation).
     */
    void init();

    /**
     * Persists content from an {@link InputStream} into private storage, associating it
     * with the specified immutable UUID storage key.
     *
     * <p>If a file already exists for this storage key, it is replaced atomically.
     * If the input stream fails or is interrupted during writing, any partial temporary
     * data is cleaned up immediately.
     *
     * @param storageKey  the non-predictable UUID identifying the document in storage
     * @param inputStream the data stream containing the file contents
     * @throws StorageException if an I/O error or security validation failure occurs
     */
    void store(UUID storageKey, InputStream inputStream);

    /**
     * Convenience method to persist raw byte array content into private storage for the
     * specified immutable UUID storage key.
     *
     * @param storageKey the non-predictable UUID identifying the document in storage
     * @param content    the binary content of the file
     * @throws StorageException if an I/O error or security validation failure occurs
     */
    void store(UUID storageKey, byte[] content);

    /**
     * Loads the file associated with the specified UUID storage key as a Spring {@link Resource}.
     *
     * @param storageKey the non-predictable UUID identifying the document in storage
     * @return the readable Resource representation of the stored file
     * @throws StorageFileNotFoundException if the file does not exist or cannot be read
     * @throws StorageException             if an unexpected I/O error occurs
     */
    Resource loadAsResource(UUID storageKey);

    /**
     * Opens an {@link InputStream} to read the file associated with the specified UUID storage key.
     *
     * <p>The caller is responsible for closing the returned stream.
     *
     * @param storageKey the non-predictable UUID identifying the document in storage
     * @return an open InputStream to the file content
     * @throws StorageFileNotFoundException if the file does not exist
     * @throws StorageException             if an unexpected I/O error occurs
     */
    InputStream loadAsStream(UUID storageKey);

    /**
     * Checks whether a file exists in storage for the specified UUID storage key.
     *
     * @param storageKey the non-predictable UUID identifying the document in storage
     * @return true if the file exists and is a regular file; false otherwise
     */
    boolean exists(UUID storageKey);

    /**
     * Returns the size in bytes of the file associated with the specified UUID storage key.
     *
     * @param storageKey the non-predictable UUID identifying the document in storage
     * @return the file size in bytes
     * @throws StorageFileNotFoundException if the file does not exist
     * @throws StorageException             if size determination fails
     */
    long getFileSize(UUID storageKey);

    /**
     * Deletes the file associated with the specified UUID storage key from private storage.
     *
     * @param storageKey the non-predictable UUID identifying the document in storage
     * @return true if the file existed and was deleted; false if it did not exist
     * @throws StorageException if deletion fails due to filesystem permissions or locks
     */
    boolean delete(UUID storageKey);

    /**
     * Resolves the canonical, normalized filesystem {@link Path} for a given UUID storage key,
     * ensuring it remains strictly contained within the designated storage directory.
     *
     * @param storageKey the non-predictable UUID identifying the document in storage
     * @return the normalized, validated Path
     * @throws StorageException if path resolution or containment validation fails
     */
    Path resolvePath(UUID storageKey);

    /**
     * Deletes all stored files in the storage root. Primarily intended for automated test cleanup.
     *
     * @throws StorageException if directory traversal or file deletion fails
     */
    void deleteAll();
}
