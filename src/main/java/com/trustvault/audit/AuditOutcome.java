package com.trustvault.audit;

/**
 * Outcome status of an audited security action.
 */
public enum AuditOutcome {
    /**
     * The business operation completed successfully and its transaction committed.
     */
    SUCCESS,

    /**
     * The operation was rejected due to an explicit authorization or security policy check.
     */
    DENIED,

    /**
     * The operation failed due to a system error, validation failure, or runtime exception.
     */
    FAILURE
}
