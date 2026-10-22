package com.trustvault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Form backing object for document creation requests.
 *
 * Validation bounds:
 * - title: required, 1 to 255 characters (trimmed)
 * - description: optional, up to 1000 characters (trimmed)
 */
public class CreateDocumentForm {

    @NotBlank(message = "Document title is required")
    @Size(min = 1, max = 255, message = "Document title must not exceed 255 characters")
    private String title;

    @Size(max = 1000, message = "Document description must not exceed 1000 characters")
    private String description;

    public CreateDocumentForm() {
    }

    public CreateDocumentForm(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title != null ? title.trim() : null;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description != null ? description.trim() : null;
    }
}
