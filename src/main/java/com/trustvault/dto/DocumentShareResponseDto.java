package com.trustvault.dto;

import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.SharePermission;

import java.time.Instant;

/**
 * Data transfer object representing document share permission grants.
 *
 * Prevents direct exposure of JPA entity internals in future HTTP controller responses.
 */
public record DocumentShareResponseDto(
        Long id,
        Long documentId,
        String granteeUsername,
        SharePermission permission,
        Instant grantedAt
) {
    public static DocumentShareResponseDto from(DocumentShare share) {
        return new DocumentShareResponseDto(
                share.getId(),
                share.getDocument().getId(),
                share.getGrantee().getUsername(),
                share.getPermission(),
                share.getGrantedAt()
        );
    }
}
