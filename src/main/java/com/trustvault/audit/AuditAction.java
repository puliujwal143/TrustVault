package com.trustvault.audit;

/**
 * Enumeration of security-relevant audit actions across TrustVault.
 *
 * Captures lifecycle events for documents, access grants, user accounts,
 * and security policy enforcement / authorization denials.
 */
public enum AuditAction {
    /**
     * Creation of a new document and initial ownership assignment.
     */
    DOCUMENT_CREATE,

    /**
     * Retrieval of document metadata or preparation for content download.
     */
    DOCUMENT_READ,

    /**
     * Modification of document metadata (title, description).
     */
    DOCUMENT_UPDATE,

    /**
     * Deletion of a document and cascading removal of its active shares.
     */
    DOCUMENT_DELETE,

    /**
     * Granting document access (READ or EDIT) to a named user.
     */
    SHARE_GRANT,

    /**
     * Modifying an existing share grant's permission level.
     */
    SHARE_UPDATE,

    /**
     * Revocation of document access for a named user.
     */
    SHARE_REVOKE,

    /**
     * Administrative deactivation of a user account and session invalidation.
     */
    USER_DEACTIVATE,

    /**
     * Administrative reactivation of a disabled user account.
     */
    USER_REACTIVATE,

    /**
     * Modification of a user account's credentials.
     */
    PASSWORD_CHANGE,

    /**
     * Authorization rejection or security policy violation.
     */
    ACCESS_DENIED,

    /**
     * Upload or replacement of a document file payload.
     */
    FILE_UPLOAD,

    /**
     * Retrieval or streaming download of a document file payload.
     */
    FILE_DOWNLOAD
}
