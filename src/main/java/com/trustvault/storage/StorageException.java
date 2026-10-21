package com.trustvault.storage;

/**
 * Base runtime exception for failures occurring within the storage engine.
 *
 * <p>Thrown when filesystem I/O, path resolution, permission, or storage
 * lifecycle operations fail unexpectedly.
 */
public class StorageException extends RuntimeException {

    public StorageException(String message) {
        super(message);
    }

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
