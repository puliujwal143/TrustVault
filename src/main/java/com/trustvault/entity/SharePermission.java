package com.trustvault.entity;

/**
 * Access permissions that a document owner can grant to other named users.
 *
 * Rules:
 * - READ: Allows viewing document metadata and reading/downloading document content.
 * - EDIT: Allows updating document metadata/content AND inherently permits reading.
 * - Ownership operations (granting/revoking shares, document deletion) are restricted to the owner.
 */
public enum SharePermission {
    /**
     * Read-only permission. Permits viewing document metadata and reading content.
     */
    READ,

    /**
     * Edit permission. Permits reading content and updating document metadata/content.
     * Inherently includes read access.
     */
    EDIT;

    /**
     * Determines whether this permission level permits reading document metadata and content.
     * Both READ and EDIT permit reading.
     *
     * @return true for all valid permissions
     */
    public boolean allowsRead() {
        return true;
    }

    /**
     * Determines whether this permission level permits modifying document metadata and content.
     *
     * @return true only for EDIT permission
     */
    public boolean allowsEdit() {
        return this == EDIT;
    }
}
