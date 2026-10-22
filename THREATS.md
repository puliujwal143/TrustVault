# TrustVault — Security Threat Model & Risk Assessment

## 1. Executive Summary & Overview

TrustVault is a secure document-sharing and management application engineered with Java 21, Spring Boot 3.3.5, Spring Security 6, Spring Data JPA, Thymeleaf, and PostgreSQL. It enables users to create and manage sensitive documents, share them with designated collaborators under strict permission boundaries, securely upload and download binary payloads, and maintain an immutable, tamper-evident audit history.

The core security mission of TrustVault is:
1. Ensure that **only authenticated and explicitly authorized users can access or modify documents and their attached files**.
2. Enforce **defense-in-depth against unauthorized data access, privilege escalation, and malicious file execution**.
3. Record all security-sensitive events in a **resilient, non-repudiable audit trail**.

This document details the threat model for TrustVault, enumerating identified threats, business and technical impacts, existing verified controls, residual risks, and verification statuses verified against the active source code and test suite.

---

## 2. Assets to Protect

The primary assets requiring protection in TrustVault include:

- **User Accounts and Credentials:** Usernames, email addresses, roles, and BCrypt password hashes stored in PostgreSQL.
- **Document Metadata:** Titles, descriptions, ownership associations, creation and update timestamps, and storage references.
- **Document Binary Payloads:** Uploaded files (PDFs, images, archives, text documents) stored in isolated local file storage outside the web root.
- **Collaborator Shares & Permissions:** Explicit access grants defining `READ` vs. `EDIT` capabilities per user per document.
- **Audit Records:** A chronological ledger documenting authentication events, authorization denials, document modifications, sharing transactions, and file downloads.
- **Application Availability & Integrity:** Host file system integrity, server memory, transaction state, and database consistency.

---

## 3. Trust Boundaries & Threat Actors

### Trust Boundaries
1. **Client / Browser vs. Server Boundary:** Untrusted network boundary. Handled via HTTPS (production), HTTP session cookies (`JSESSIONID`), and Synchronizer Token Pattern CSRF tokens.
2. **Web Controller vs. Service Layer:** Parameter validation, authentication context propagation, and model-view mapping.
3. **Service Layer vs. File Storage Subsystem:** Boundary between metadata state and physical storage. File keys are decoupled into random UUIDs; direct client-specified filenames are never used for file system paths.
4. **Service Layer vs. Database (JPA / PostgreSQL):** Managed transactional boundary enforcing entity relationships, schema constraints, and audit persistence.

### Threat Actors
- **Unauthenticated External Attacker:** Tries to enumerate resources, bypass authentication, forge requests, or execute denial-of-service attacks.
- **Authenticated Malicious User (Standard User):** Attempts to access or tamper with documents belonging to other users without authorization (BOLA/IDOR), escalate permissions, or upload malicious payloads.
- **Authorized Collaborator with READ Permission:** Attempts to execute unauthorized updates, upload or overwrite files, or manage sharing rules.
- **Privileged Application Administrator (`ROLE_ADMIN`):** Expected to manage users, but restricted by a zero-trust policy from viewing or editing private user documents without an explicit share grant.
- **Privileged Infrastructure / Database Administrator:** Threat actor with direct host or SQL shell access outside application runtime boundaries.

---

## 4. Threat Analysis & Mitigations

### 4.1. Broken Object Level Authorization (BOLA / IDOR)

- **Threat:** An authenticated attacker attempts to view, download, modify, or delete a document owned by another user by manipulating the numeric document ID (e.g., requesting `/documents/105` or `/api/documents/105/file`).
- **Potential Impact:** Unauthorized disclosure of confidential document metadata and attached files; data tampering or unauthorized destruction.
- **Existing Verified Controls:**
  - `DocumentAuthorizationService.getAuthorizedDocument(Long documentId, String username, SharePermission requiredPermission)` validates that the current user is either the document owner or an active collaborator granted the necessary permission.
  - **Information Leakage Reduction:** When a user requests a document for which they have no share or ownership, the service throws `ResourceNotFoundException("Document not found with id: " + documentId)`. As handled in `GlobalExceptionHandler.handleResourceNotFound`, the application responds with `HTTP 404 Not Found` rather than `403 Forbidden`. This reduces information leakage by preventing unauthorized attackers from reliably distinguishing between non-existent document IDs and existing unshared document IDs via HTTP status codes alone.
  - **Admin Zero-Trust:** As implemented in `DocumentAuthorizationService.authorizeDocument`, users with `ROLE_ADMIN` are explicitly subjected to standard document authorization rules and cannot read or edit private documents without explicit ownership or a shared grant.
- **Residual Risk:**
  - While HTTP 404 significantly reduces information leakage through response status codes, timing variations or sequential ID allocation could still provide subtle side-channel hints to an advanced attacker.
- **Verification Status:** `VERIFIED` (Covered in `DocumentAuthorizationTest`, `DocumentFileUploadServiceTest`, and `DocumentFileDownloadControllerTest`).

---

### 4.2. Privilege Escalation (READ vs. EDIT, Collaborator vs. Owner)

- **Threat:** A collaborator with `READ` access attempts to edit document metadata or upload replacement files. Alternatively, a collaborator with `EDIT` access attempts to perform owner-only operations such as deleting the document or granting/revoking shares to third parties.
- **Potential Impact:** Unauthorized metadata alteration, unauthorized file replacement, and unauthorized expansion of access control lists.
- **Existing Verified Controls:**
  - **Granular Permissions:** `DocumentService.uploadFile` explicitly requires `SharePermission.EDIT`. Collaborators with only `READ` permissions are rejected with `AccessDeniedException` (`HTTP 403`).
  - **Owner Exclusivity:** `DocumentAuthorizationService.authorizeDocumentForOwner(Long documentId, String username)` is enforced on all share management endpoints (`DocumentShareService.grantAccess`, `revokeAccess`, `listShares`) and document deletion (`DocumentService.deleteDocument`). Non-owner collaborators receive an `AccessDeniedException` (`HTTP 403`) if the document is shared with them, or `ResourceNotFoundException` (`HTTP 404`) if unshared.
- **Residual Risk:**
  - Low. Business logic strictly isolates ownership checks from collaborator permission checks.
- **Verification Status:** `VERIFIED` (Covered in `DocumentShareRestControllerTest` and `DocumentFileUploadControllerTest`).

---

### 4.3. Malicious File Uploads & Path Traversal

- **Threat:** An attacker uploads executable binaries, shell scripts, malicious archives (Zip-Slip, Zip-Bomb), or files disguised with false MIME types or extensions to achieve remote code execution, file overwrite, or server crash.
- **Potential Impact:** Remote code execution (RCE), host file system compromise, disk space exhaustion, denial of service.
- **Existing Verified Controls:**
  - **Size Boundaries:** `FileValidationService` enforces a strict 10 MiB limit (`MAX_FILE_SIZE_BYTES = 10_485_760L`) at the service layer prior to persistent storage.
  - **Magic Byte Validation:** `FileValidationService.validateFilePayload` inspects the initial byte sequences against verified signatures for PDF (`%PDF-`), PNG, JPEG, and ZIP. Plaintext/code files are verified for valid UTF-8 encoding and immediately rejected if embedded NUL bytes (`0x00`) are detected.
  - **Zip Decompression Guards:** Zip files are inspected entry-by-entry without extraction. The application limits total archive entries to 1,000, caps total uncompressed size at 50 MiB, enforces safe compression ratios, and verifies that entry names do not contain path traversal sequences (`../`, Zip-Slip).
  - **Storage Isolation & Path Traversal Defense:** `LocalStorageService` stores files in an isolated root (`./private-storage/uploads`) outside the web root. Files are stored using random UUID storage keys (`{storageKey}.bin`), never the user-supplied filename. File paths are normalized and verified to reside strictly within the storage directory. Symlinks are explicitly rejected using `LinkOption.NOFOLLOW_LINKS`. Atomic staging is used to prevent partial file writes.
- **Residual Risk:**
  - Deep heuristic or signature-based anti-malware scanning (e.g., ClamAV) is not present. A syntactically valid PDF containing a client-side Adobe exploit or malicious macro could pass validation.
- **Verification Status:** `VERIFIED` (Covered in `FileValidationServiceTest` [50 tests] and `LocalStorageServiceTest` [23 tests]).

---

### 4.4. File Tampering & Integrity Degradation

- **Threat:** An attacker with local access, backup access, or through silent disk corruption modifies a stored binary payload on the file system.
- **Potential Impact:** Serving altered, corrupted, or malicious files to legitimate users during download.
- **Existing Verified Controls:**
  - **Checksum Generation:** During upload, `FileValidationService.calculateSha256(byte[])` computes the SHA-256 digest of the payload and stores it in `documents.file_checksum`.
  - **Pre-Stream Download Verification:** In `DocumentService.downloadFile`, before releasing file bytes to the client, the stored file is streamed through `calculateSha256(InputStream)`. The computed hash is compared to the database checksum using constant-time comparison (`MessageDigest.isEqual`).
  - **Fail-Closed Execution:** If the checksum mismatches, `DocumentService` immediately aborts the operation and throws `StorageException`, returning `HTTP 500` via `GlobalExceptionHandler` and delivering zero file bytes to the requester.
  - **Header Injection Defense:** `DocumentController.sanitizeFilenameForHeader` strips carriage returns (`\r`), newlines (`\n`), quotes, and semicolons from the `Content-Disposition` header to prevent HTTP response splitting.
- **Residual Risk:**
  - Low for data tampering detection. Files are stored unencrypted at rest on disk, meaning physical read access is governed by host OS access control lists.
- **Verification Status:** `VERIFIED` (Covered in `DocumentFileDownloadControllerTest` [14 tests]).

---

### 4.5. Authentication & Session Attacks

- **Threat:** Credential stuffing, brute-force password guessing, session fixation, session hijacking, or continued access after password reset / account deactivation.
- **Potential Impact:** Account takeover, unauthorized access to all user documents and shares.
- **Existing Verified Controls:**
  - **Password Hashing:** Passwords are encrypted using Spring Security's `BCryptPasswordEncoder` configured with work factor 12.
  - **Session Fixation Defense:** Configured in `SecurityConfig` via `sessionFixation(fixation -> fixation.changeSessionId())`, creating a new session ID upon successful login while preserving session attributes.
  - **CSRF-Protected Logout:** Logout is restricted to `POST /logout` requiring a valid CSRF token. The logout handler explicitly invalidates the `HttpSession`, clears the `SecurityContext`, and clears the `JSESSIONID` cookie (`Max-Age=0`).
  - **Session Invalidation on Deactivation / Reset:** `UserService.deactivateUser` sets `enabled = false` and registers a post-commit transaction hook via `TransactionSynchronizationManager.registerSynchronization` to revoke all active sessions for the user through Spring Security's `SessionRegistry`.
- **Residual Risk:**
  - **In-Memory `SessionRegistry` Scalability:** The current `SessionRegistryImpl` stores sessions in JVM heap memory. In a multi-node horizontal deployment, session invalidation on Node A does not propagate to Node B without an external distributed session store (e.g., Spring Session with Redis).
  - **Lack of Application Rate Limiting:** The `/login` endpoint lacks rate limiting or account lockout, leaving it vulnerable to automated brute-force attacks if not mitigated by an upstream reverse proxy.
- **Verification Status:** `VERIFIED` (Covered in `AuthenticationIntegrationTest`, `LogoutIntegrationTest`, and `UserServiceSessionInvalidationTest`).

---

### 4.6. Cross-Site Request Forgery (CSRF)

- **Threat:** An attacker tricks an authenticated user's browser into executing state-changing operations (creating documents, uploading files, changing shares, deactivating accounts, logging out) without their consent.
- **Potential Impact:** Unauthorized modification of resources, privilege changes, or forced logout.
- **Existing Verified Controls:**
  - Spring Security CSRF protection is active by default across all mutating HTTP methods (`POST`, `PUT`, `DELETE`).
  - Standard HTML forms include Thymeleaf CSRF hidden tokens (`_csrf`).
  - REST endpoints (e.g., `/api/documents/{id}/file`, `/api/documents/{id}/shares/**`) validate the `X-CSRF-TOKEN` header or form token.
- **Residual Risk:**
  - Low. CSRF protection is enforced globally and verified across web and REST controllers.
- **Verification Status:** `VERIFIED` (Covered in `SecurityConfig`, `DocumentFileUploadControllerTest`, and `DocumentShareRestControllerTest`).

---

### 4.7. Audit Log Tampering & Evasion

- **Threat:** A malicious user or rogue insider performs unauthorized actions and rolls back the transaction or alters the audit records to evade detection.
- **Potential Impact:** Loss of non-repudiation, blind spots in incident response, undetected data breaches.
- **Existing Verified Controls:**
  - **Autonomous Denial Logging:** `AuditService.recordSecurityDenial` runs with `@Transactional(propagation = Propagation.REQUIRES_NEW)`. Security denial records are committed immediately in an independent database transaction and persist even if the outer business transaction fails or rolls back.
  - **Transactional Consistency for Business Events:** Standard audit events (`recordEvent`) run with `Propagation.REQUIRED`, ensuring audit records are committed atomically alongside successful business operations.
  - **Application-Level Immutability:** The `AuditEvent` entity defines `@Column(updatable = false)` across audit columns and exposes no mutator/setter methods. `AuditEventRepository` exposes only append and read methods.
- **Residual Risk & DBA Distinction:**
  - **Critical Distinction:** Immutability is enforced strictly at the **application and JPA layer**. It does **not** protect against a privileged PostgreSQL database administrator or an attacker with direct SQL shell access, who could modify or delete rows in the `audit_events` table without database-level append-only enforcement (e.g., database triggers or write-once storage).
- **Verification Status:** `VERIFIED` (Covered in `BusinessAuditIntegrationTest` and `AuditEventPersistenceTest`).

---

### 4.8. Sensitive Information Disclosure

- **Threat:** Error messages, stack traces, internal storage keys, or database exception details are returned to the client, assisting attackers in footprinting the environment.
- **Potential Impact:** Exposure of internal file paths, framework versions, database schema, or storage layout.
- **Existing Verified Controls:**
  - `GlobalExceptionHandler` intercepts all standard and uncaught exceptions (`StorageException`, `StorageFileNotFoundException`, `ResourceNotFoundException`, `AccessDeniedException`, `MethodArgumentNotValidException`, `Exception`).
  - Responses are mapped to a sanitized `ErrorResponseDto` containing only a timestamp, HTTP status code, and generic error message.
  - Absolute file system paths, UUID storage keys, and raw stack traces are logged only to secure server logs and are never sent to the client.
- **Residual Risk:**
  - Low. Exception responses are centralized and uniform.
- **Verification Status:** `VERIFIED` (Covered in `GlobalExceptionHandlerTest`).

---

### 4.9. Credential Exposure

- **Threat:** Plaintext passwords, password hashes, or session tokens are leaked through API responses, debug endpoints, or audit logs.
- **Potential Impact:** Immediate account compromise.
- **Existing Verified Controls:**
  - User DTOs (`UserDto`) never include password fields.
  - Password hashes are stored with BCrypt (strength 12) in `users.password_hash`.
  - Development seed and reset mechanisms (`DevUserInitializer`, `DevPasswordResetRunner`) require explicit opt-in flags, are active only under the `dev` profile, and never print or log plaintext passwords.
  - `AuditService` strictly excludes passwords, tokens, and raw file bytes from audit log metadata.
- **Residual Risk:**
  - Low. Credential hygiene is maintained across services, DTOs, and logs.
- **Verification Status:** `VERIFIED` (Covered in `DevUserInitializerTest`, `UserServiceTest`, and audit tests).

---

### 4.10. Denial of Service (DoS)

- **Threat:** An attacker sends oversized files, deeply nested or highly compressed zip archives (zip bombs), or high volumes of requests to exhaust system resources.
- **Potential Impact:** Application unresponsiveness, out-of-memory errors, disk saturation.
- **Existing Verified Controls:**
  - Hard limit of 10 MiB per file upload enforced before storage.
  - Zip decompression bounds: max 1,000 entries, max 50 MiB uncompressed size, compression ratio checks.
  - Streaming SHA-256 computation using fixed 8 KiB buffers bounds memory consumption during upload and download.
- **Residual Risk:**
  - **Missing Application-Level Rate Limiting:** High-frequency requests against `/login` or file endpoints are not throttled by the application.
- **Verification Status:** `PARTIALLY VERIFIED` (File and memory bounds verified; rate limiting not implemented).

---

## 5. Summary of Residual Security Risks

The four key residual security risks identified in the audit and their operational contexts are:

| # | Residual Risk | Severity | Description & Architectural Context |
| :--- | :--- | :--- | :--- |
| **1** | **Missing Application-Level Rate Limiting** | **Medium** | Neither `/login` nor `/api/documents/**` endpoints implement rate limiting or request throttling in code. Mitigated only if deployed behind a configured reverse proxy or WAF. |
| **2** | **In-Memory `SessionRegistry` Scalability Bounds** | **Low-to-Medium** | `SessionRegistryImpl` stores session references in JVM heap. In a multi-node deployment, account deactivation or password resets on Node A do not invalidate sessions on Node B without Spring Session / Redis. |
| **3** | **Absence of Antivirus / Heuristic Malware Scanning** | **Low** | `FileValidationService` inspects headers, magic bytes, and archive structures, but does not execute heuristic or signature-based anti-malware analysis (e.g., ClamAV) for embedded malicious content in valid PDFs or images. |
| **4** | **Unencrypted File Blobs At Rest** | **Low** | Stored files in `private-storage/uploads/{storageKey}.bin` rely entirely on host OS file system permissions and disk security, rather than application-managed envelope encryption (e.g., AES-256 GCM). |

---

## 6. Security Verification Checklist

The following test suites in `src/test/java/com/trustvault/` verify the security controls documented in this threat model:

- [x] **Document Authorization & IDOR Protection:** `com.trustvault.service.DocumentAuthorizationTest`
- [x] **File Upload Authorization & Rollback Safety:** `com.trustvault.service.DocumentFileUploadServiceTest`
- [x] **File Validation, Magic Bytes & Zip-Slip/Bomb Defenses:** `com.trustvault.storage.FileValidationServiceTest`
- [x] **Path Traversal & Storage Isolation:** `com.trustvault.storage.LocalStorageServiceTest`
- [x] **Upload Controller Permissions & Security:** `com.trustvault.controller.DocumentFileUploadControllerTest`
- [x] **Download Controller Checksum Verification & Fail-Closed:** `com.trustvault.controller.DocumentFileDownloadControllerTest`
- [x] **Sharing REST Controller Permissions & IDOR Defense:** `com.trustvault.controller.DocumentShareRestControllerTest`
- [x] **Authentication, CSRF & Session Management:** `com.trustvault.security.AuthenticationIntegrationTest`
- [x] **CSRF-Protected Logout & Session Clearing:** `com.trustvault.security.LogoutIntegrationTest`
- [x] **Account Deactivation & Session Invalidation:** `com.trustvault.service.UserServiceSessionInvalidationTest`
- [x] **Audit Logging & Transaction Propagation (`REQUIRES_NEW`):** `com.trustvault.service.BusinessAuditIntegrationTest`
- [x] **Audit Immutability & Persistence:** `com.trustvault.repository.AuditEventPersistenceTest`
- [x] **Exception Handling & Information Leakage Prevention:** `com.trustvault.exception.GlobalExceptionHandlerTest`

*Test Suite Execution: 331 tests run, 331 passing, 0 failures, 0 errors, 6 platform-skipped.*

---

## 7. Prioritized Future Security Improvements

1. **Implement Application-Level Rate Limiting:**
   - Integrate Bucket4j or Spring Cloud Gateway request filters on `/login`, `/api/documents/**`, and share endpoints to mitigate credential stuffing and denial-of-service attempts.
2. **Cluster-Aware Distributed Session Management:**
   - Migrate `SessionRegistryImpl` to Spring Session with Redis to ensure consistent session revocation across multi-node clusters.
3. **At-Rest Envelope Encryption for Storage Blobs:**
   - Implement AES-256 GCM envelope encryption for stored binary files in `./private-storage/uploads` using keys managed via a secure Key Management Service (KMS) or environment secret.
4. **Antivirus / Anti-Malware Integration:**
   - Integrate an asynchronous or inline scanning daemon (e.g., ClamAV via TCP/socket) inside `FileValidationService` to detect malicious active content in valid file payloads.
5. **Database-Level Audit Protection:**
   - Implement PostgreSQL row-level locks or trigger-based append-only controls on `audit_events` to provide non-repudiation even against privileged database accounts.
