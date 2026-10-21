package com.trustvault.entity;

/**
 * User roles within TrustVault.
 *
 * Prefixed with 'ROLE_' to align with Spring Security's default role conventions.
 */
public enum Role {
    /**
     * Standard user role.
     * Operates within granted workspace and document permissions.
     */
    ROLE_USER,

    /**
     * Administrator role.
     * Manages platform configuration and user accounts.
     * NOTE: Does NOT grant automatic content-level access to private user documents.
     */
    ROLE_ADMIN
}
