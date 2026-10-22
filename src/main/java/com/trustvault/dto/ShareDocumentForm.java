package com.trustvault.dto;

import com.trustvault.entity.SharePermission;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Form backing object for document share creation and update requests.
 *
 * Validation bounds:
 * - granteeUsername: required, 1 to 50 characters (trimmed)
 * - permission: required, READ or EDIT
 */
public class ShareDocumentForm {

    @NotBlank(message = "Recipient username is required")
    @Size(min = 1, max = 50, message = "Recipient username must not exceed 50 characters")
    private String granteeUsername;

    @NotNull(message = "Permission level is required")
    private SharePermission permission = SharePermission.READ;

    public ShareDocumentForm() {
    }

    public ShareDocumentForm(String granteeUsername, SharePermission permission) {
        this.granteeUsername = granteeUsername;
        this.permission = permission;
    }

    public String getGranteeUsername() {
        return granteeUsername;
    }

    public void setGranteeUsername(String granteeUsername) {
        this.granteeUsername = granteeUsername != null ? granteeUsername.trim() : null;
    }

    public String getUsername() {
        return granteeUsername;
    }

    public void setUsername(String username) {
        this.granteeUsername = username != null ? username.trim() : null;
    }

    public SharePermission getPermission() {
        return permission;
    }

    public void setPermission(SharePermission permission) {
        this.permission = permission;
    }
}
