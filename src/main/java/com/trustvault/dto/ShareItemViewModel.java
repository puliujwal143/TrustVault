package com.trustvault.dto;

import com.trustvault.entity.DocumentShare;

import java.time.Instant;

/**
 * Safe view model representing an active share grant on a document.
 *
 * Security Requirements:
 * - Decouples view rendering from JPA entities and lazy associations,
 *   strictly adhering to spring.jpa.open-in-view=false.
 * - Exposes only client-safe fields: grantee username, permission level, and granted timestamp.
 * - NEVER exposes user password hashes, account internals, or database entity references.
 */
public record ShareItemViewModel(
        Long id,
        String granteeUsername,
        String permission,
        Instant grantedAt
) {
    public static ShareItemViewModel from(DocumentShare share) {
        if (share == null) {
            return null;
        }
        String grantee = share.getGrantee() != null ? share.getGrantee().getUsername() : null;
        String perm = share.getPermission() != null ? share.getPermission().name() : null;
        return new ShareItemViewModel(
                share.getId(),
                grantee,
                perm,
                share.getGrantedAt()
        );
    }
}
