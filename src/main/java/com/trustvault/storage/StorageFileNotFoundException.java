package com.trustvault.storage;

/**
 * Exception thrown when a requested file does not exist or is unreadable in the storage engine.
 */
public class StorageFileNotFoundException extends StorageException {

    public StorageFileNotFoundException(String message) {
        super(message);
    }

    public StorageFileNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
