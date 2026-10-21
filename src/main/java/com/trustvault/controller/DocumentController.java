package com.trustvault.controller;

import com.trustvault.dto.DocumentResponseDto;
import com.trustvault.entity.Document;
import com.trustvault.service.DocumentService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * REST controller managing document resources and file attachments.
 *
 * Security Requirements:
 * - Default deny: all endpoints require authentication (enforced by SecurityConfig).
 * - CSRF protection is active on mutating endpoints.
 * - Authenticated username is resolved via Spring Security Authentication principal.
 * - Delegates validation, storage, authorization, transaction lifecycle, and audit
 *   logging to DocumentService without duplicating business logic.
 * - Responses return DocumentResponseDto which strictly suppresses physical storage keys,
 *   filesystem paths, checksums, and raw binary contents.
 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final DocumentService documentService;

    public DocumentController(DocumentService documentService) {
        this.documentService = documentService;
    }

    /**
     * Secure file upload endpoint attaching or replacing a file for an existing document.
     *
     * @param id             the target document ID
     * @param file           the multipart file payload (field name 'file')
     * @param authentication the authenticated user principal from Spring Security
     * @param request        the incoming HTTP servlet request
     * @return the updated document metadata as DocumentResponseDto with HTTP 200 OK
     */
    @PostMapping(value = "/{id}/file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<DocumentResponseDto> uploadFile(
            @PathVariable("id") Long id,
            @RequestParam(value = "file", required = false) MultipartFile file,
            Authentication authentication,
            HttpServletRequest request) {

        String username = authentication != null ? authentication.getName() : null;
        String clientIp = request != null ? request.getRemoteAddr() : null;

        Document updatedDocument = documentService.uploadFile(id, file, username, clientIp);
        return ResponseEntity.ok(DocumentResponseDto.from(updatedDocument));
    }
}
