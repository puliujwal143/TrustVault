package com.trustvault.controller;

import com.trustvault.dto.CreateDocumentForm;
import com.trustvault.dto.DocumentDownloadDto;
import com.trustvault.dto.DocumentResponseDto;
import com.trustvault.dto.DocumentShareResponseDto;
import com.trustvault.dto.UpdateDocumentForm;
import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.SharePermission;
import com.trustvault.service.DocumentService;
import com.trustvault.service.DocumentShareService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * REST controller managing document resources, file attachments, and sharing permissions.
 *
 * Security Requirements:
 * - Default deny: all endpoints require authentication (enforced by SecurityConfig).
 * - CSRF protection is active on mutating endpoints.
 * - Authenticated username is resolved via Spring Security Authentication principal.
 * - Delegates validation, storage, authorization, transaction lifecycle, and audit
 *   logging to DocumentService and DocumentShareService without duplicating business logic.
 * - Responses return DocumentResponseDto / DocumentShareResponseDto which strictly suppress
 *   physical storage keys, filesystem paths, checksums, and raw binary contents.
 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final DocumentService documentService;
    private final DocumentShareService documentShareService;

    public DocumentController(DocumentService documentService) {
        this(documentService, null);
    }

    @Autowired
    public DocumentController(DocumentService documentService, DocumentShareService documentShareService) {
        this.documentService = documentService;
        this.documentShareService = documentShareService;
    }

    /**
     * Creates a new document metadata record.
     *
     * @param form           document creation form containing title and optional description
     * @param authentication authenticated user principal
     * @return created DocumentResponseDto with HTTP 201 Created
     */
    @PostMapping
    public ResponseEntity<DocumentResponseDto> createDocument(
            @Valid @RequestBody CreateDocumentForm form,
            Authentication authentication) {
        String username = authentication != null ? authentication.getName() : null;
        Document document = documentService.createDocument(form.getTitle(), form.getDescription(), username);
        return ResponseEntity.status(HttpStatus.CREATED).body(DocumentResponseDto.from(document));
    }

    /**
     * Lists all documents accessible to the authenticated caller (owned and shared).
     *
     * @param authentication authenticated user principal
     * @return list of accessible DocumentResponseDto items
     */
    @GetMapping
    public ResponseEntity<List<DocumentResponseDto>> listDocuments(Authentication authentication) {
        String username = authentication != null ? authentication.getName() : null;
        List<Document> documents = documentService.listAccessibleDocuments(username);
        return ResponseEntity.ok(documents.stream().map(DocumentResponseDto::from).toList());
    }

    /**
     * Retrieves sanitized metadata for an accessible document.
     *
     * @param id             target document ID
     * @param authentication authenticated user principal
     * @return DocumentResponseDto with HTTP 200 OK
     */
    @GetMapping("/{id}")
    public ResponseEntity<DocumentResponseDto> getDocument(
            @PathVariable("id") Long id,
            Authentication authentication) {
        String username = authentication != null ? authentication.getName() : null;
        Document document = documentService.getDocument(id, username);
        return ResponseEntity.ok(DocumentResponseDto.from(document));
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

    /**
     * Secure file download endpoint retrieving the binary file payload for an authorized document.
     *
     * <p>Security & Verification Guarantees:
     * <ul>
     *   <li>Enforces authentication via Spring Security (requires authenticated principal).</li>
     *   <li>Enforces document-level authorization (owner, READ grantee, or EDIT grantee).</li>
     *   <li>Returns HTTP 404 for unshared users, revoked users, or non-existent documents (anti-IDOR).</li>
     *   <li>Verifies SHA-256 checksum before streaming bytes; corrupted files fail closed with HTTP 500.</li>
     *   <li>Sanitizes filename for Content-Disposition header to prevent HTTP header injection.</li>
     *   <li>Never exposes storage UUIDs, filesystem paths, or internal checksums.</li>
     * </ul>
     *
     * @param id             target document ID
     * @param authentication authenticated user principal from Spring Security
     * @param request        incoming HTTP servlet request
     * @return ResponseEntity containing the streaming Resource with safe headers
     */
    @GetMapping("/{id}/download")
    public ResponseEntity<Resource> downloadFile(
            @PathVariable("id") Long id,
            Authentication authentication,
            HttpServletRequest request) {

        String username = authentication != null ? authentication.getName() : null;
        String clientIp = request != null ? request.getRemoteAddr() : null;

        DocumentDownloadDto download = documentService.downloadFile(id, username, clientIp);

        // Sanitize filename to prevent HTTP header injection (CRLF, quotes)
        String safeFilename = sanitizeFilenameForHeader(download.originalFilename());

        ContentDisposition contentDisposition = ContentDisposition.attachment()
                .filename(safeFilename)
                .build();

        MediaType mediaType;
        try {
            mediaType = MediaType.parseMediaType(download.contentType());
        } catch (Exception e) {
            mediaType = MediaType.APPLICATION_OCTET_STREAM;
        }

        return ResponseEntity.ok()
                .contentType(mediaType)
                .headers(headers -> headers.setContentDisposition(contentDisposition))
                .header(HttpHeaders.CONTENT_LENGTH, String.valueOf(download.fileSize()))
                .body(download.resource());
    }

    private String sanitizeFilenameForHeader(String originalFilename) {
        if (originalFilename == null || originalFilename.isBlank()) {
            return "document";
        }
        // Strip carriage returns and line feeds to prevent response splitting / header injection
        String sanitized = originalFilename.replaceAll("[\\r\\n]", "_")
                .replace("\"", "")
                .replace(";", "_")
                .trim();
        return sanitized.isEmpty() ? "document" : sanitized;
    }

    /**
     * Updates document metadata (title and description) (owner or EDIT collaborator).
     *
     * @param id             target document ID
     * @param form           request payload containing title and description
     * @param authentication authenticated user principal
     * @return updated DocumentResponseDto
     */
    @PutMapping("/{id}")
    public ResponseEntity<DocumentResponseDto> updateDocument(
            @PathVariable("id") Long id,
            @Valid @RequestBody UpdateDocumentForm form,
            Authentication authentication) {

        String username = authentication != null ? authentication.getName() : null;
        Document updated = documentService.updateDocument(id, form.getTitle(), form.getDescription(), username);
        return ResponseEntity.ok(DocumentResponseDto.from(updated));
    }

    /**
     * Deletes a document and its shares/payload (owner-only).
     *
     * @param id             target document ID
     * @param authentication authenticated user principal
     * @return HTTP 204 No Content
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteDocument(
            @PathVariable("id") Long id,
            Authentication authentication) {

        String ownerUsername = authentication != null ? authentication.getName() : null;
        documentService.deleteDocument(id, ownerUsername);
        return ResponseEntity.noContent().build();
    }

    /**
     * Grants or updates access permissions for a document collaborator.
     *
     * @param id              target document ID
     * @param granteeUsername recipient username
     * @param usernameParam   fallback recipient username param
     * @param permission      access permission level (READ or EDIT)
     * @param authentication  authenticated user principal
     * @return created or updated DocumentShareResponseDto
     */
    @PostMapping("/{id}/shares")
    public ResponseEntity<DocumentShareResponseDto> grantShare(
            @PathVariable("id") Long id,
            @RequestParam(value = "granteeUsername", required = false) String granteeUsername,
            @RequestParam(value = "username", required = false) String usernameParam,
            @RequestParam(value = "permission", defaultValue = "READ") SharePermission permission,
            Authentication authentication) {

        String ownerUsername = authentication != null ? authentication.getName() : null;
        String grantee = (granteeUsername != null && !granteeUsername.isBlank())
                ? granteeUsername.trim()
                : (usernameParam != null ? usernameParam.trim() : null);

        if (grantee == null || grantee.isBlank()) {
            throw new IllegalArgumentException("Grantee username is required");
        }

        DocumentShare share = documentShareService.grantAccess(id, grantee, permission, ownerUsername);
        return ResponseEntity.ok(DocumentShareResponseDto.from(share));
    }

    /**
     * Revokes access permissions for a document collaborator.
     *
     * @param id              target document ID
     * @param granteeUsername recipient username to revoke
     * @param authentication  authenticated user principal
     * @return HTTP 204 No Content
     */
    @DeleteMapping("/{id}/shares/{granteeUsername}")
    public ResponseEntity<Void> revokeShare(
            @PathVariable("id") Long id,
            @PathVariable("granteeUsername") String granteeUsername,
            Authentication authentication) {

        String ownerUsername = authentication != null ? authentication.getName() : null;
        documentShareService.revokeAccess(id, granteeUsername, ownerUsername);
        return ResponseEntity.noContent().build();
    }

    /**
     * Lists active share grants for a document (owner-only).
     *
     * @param id             target document ID
     * @param authentication authenticated user principal
     * @return list of active share grants
     */
    @GetMapping("/{id}/shares")
    public ResponseEntity<List<DocumentShareResponseDto>> listShares(
            @PathVariable("id") Long id,
            Authentication authentication) {

        String ownerUsername = authentication != null ? authentication.getName() : null;
        List<DocumentShare> shares = documentShareService.listShares(id, ownerUsername);
        return ResponseEntity.ok(shares.stream().map(DocumentShareResponseDto::from).toList());
    }
}
