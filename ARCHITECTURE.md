# TrustVault — Architecture & Security Blueprint

This document details the architectural design, component responsibilities, data flows, and security boundaries implemented in **TrustVault**. It serves as an architectural reference and evaluator guide, describing both the active production implementation and identified residual risks.

For comprehensive threat modeling, vulnerability classifications, and risk assessments, refer to the companion document [`THREATS.md`](file:///d:/TrustVault/THREATS.md).

---

## 1. Architectural Overview & Technology Stack

TrustVault is engineered as a secure, defense-in-depth document management monolith. It employs a clean multi-tiered architecture with unidirectional layer dependencies, strict principle of least privilege, and decoupled storage mechanisms.

- **Production Deployment:** [https://trustvault-axea.onrender.com](https://trustvault-axea.onrender.com)
- **Deployment Platform:** Render (Docker runtime, multi-stage build, non-root system user)
- **Cloud Database:** Neon PostgreSQL
- **Cloud Storage:** Convex Cloud Storage (HTTP Actions)

### Core Technology Stack
- **Runtime & Language:** Java 21 (LTS)
- **Framework:** Spring Boot 3.3.5
- **Security Engine:** Spring Security 6 (Form Login, Synchronizer Token CSRF, Session Fixation Migration, Concurrent Session Management, Role-Based & Attribute-Based Authorization)
- **Persistence & ORM:** Spring Data JPA / Hibernate with PostgreSQL Dialect
- **Database:** PostgreSQL 15+ / Neon PostgreSQL (Relational store for user accounts, document metadata, sharing grants, and immutable audit events)
- **Presentation Layer:** Thymeleaf 3 with Spring Security Layout Dialect (Server-side rendering, contextual authorization fragments, CSRF integration)
- **Blob Storage Subsystem:** Pluggable `StorageService` interface with two implementations:
  - `LocalStorageService`: Local private file storage isolated outside the application document root
  - `ConvexStorageService`: Secure cloud document storage via Convex HTTP Actions with Bearer token authentication
- **Build & Dependency Tooling:** Apache Maven with Maven Wrapper (`mvnw`)

---

## 2. Layered Architecture & Component Responsibilities

The system is organized into distinct, decoupled architectural layers:

```
[ Client Request: Browser / API Client ]
                   │
                   ▼
┌────────────────────────────────────────────────────────┐
│               Spring Security Filter Chain             │
│  - CSRF Token Validation (Synchronizer Token Pattern)  │
│  - Session Authentication & Fixation Migration         │
│  - Concurrent Session Tracking (SessionRegistry)       │
│  - HTTP Header Hardening (Cache-Control, nosniff, etc.)│
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                   Controller Layer                     │
│  - Web View Controllers (Thymeleaf Model & Routing)    │
│  - REST API Controllers (JSON / Multipart Endpoints)   │
│  - Request DTO Validation (@Valid, Bean Validation)    │
│  - Filename Header Sanitization (CRLF & Quote Defense) │
└─────────────┬────────────────────────────┬─────────────┘
              │ (Web / REST Flows)         │ (Exceptions)
              ▼                            ▼
┌──────────────────────────────┐ ┌───────────────────────┐
│        Service Layer         │ │GlobalExceptionHandler │
│  - DocumentAuthorization     │ │ - Sanitized ErrorDTO  │
│  - DocumentService           │ │ - Anti-Enumeration 404│
│  - DocumentShareService      │ │ - No Stack Traces     │
│  - UserService               │ └───────────────────────┘
│  - FileValidationService     │
│  - AuditService (Tx-Aware)   │
└───────┬──────────────┬───────┘
        │              │
        ▼              ▼
┌──────────────────┐ ┌──────────────────────────────────────────────┐
│ Repository Layer │ │            Storage Subsystem                 │
│ (Spring Data JPA)│ │         (StorageService Interface)           │
│ - Param Queries  │ │  ┌──────────────────────┬──────────────────┐ │
│ - Zero Raw SQL   │ │  │ LocalStorageService  │ConvexStorageServ.│ │
│ - Scoped Selects │ │  │ (./private-storage/) │ (Convex HTTPS)   │ │
└────────┬─────────┘ └──┴───────────┬──────────┴────────┬─────────┴─┘
         │                          │                   │
         ▼                          ▼                   ▼
┌──────────────────┐      ┌───────────────────┐ ┌───────────────────┐
│ PostgreSQL Store │      │ Physical OS Disk  │ │Convex Cloud Store │
└──────────────────┘      └───────────────────┘ └───────────────────┘
```

### A. Security Filter Chain (`com.trustvault.security`)
- **Primary Role:** Authenticate callers, enforce session management policies, and validate CSRF tokens prior to controller execution.
- **Responsibilities:**
  - Enforce authentication on all protected routes while maintaining explicit whitelists (`/login`, `/css/**`, `/js/**`, `/api/health`).
  - Provide session fixation protection by issuing a fresh session ID upon authentication (`changeSessionId()`).
  - Intercept logout requests via `POST /logout`, invalidating the session, clearing the `SecurityContext`, and expiring cookies.
  - Track active sessions via an in-memory `SessionRegistry` for concurrency tracking and post-commit invalidation.

### B. Controller Layer (`com.trustvault.controller`)
- **Primary Role:** Handle HTTP protocol contracts, request deserialization, parameter validation, and view/response rendering.
- **Responsibilities:**
  - **Web View Controllers:** [`AuthController`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/AuthController.java), [`DashboardController`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/DashboardController.java), [`DocumentController`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/DocumentController.java), and [`AuditViewController`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/AuditViewController.java) manage HTML page navigation and UI state.
  - **REST Controllers:** [`DocumentFileUploadController`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/DocumentFileUploadController.java), [`DocumentFileDownloadController`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/DocumentFileDownloadController.java), and [`DocumentShareRestController`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/DocumentShareRestController.java) manage programmatic data exchange.
  - Sanitize HTTP response headers (e.g., stripping carriage returns, line feeds, semicolons, and quotes from `Content-Disposition` in [`DocumentController.sanitizeFilenameForHeader`](file:///d:/TrustVault/src/main/java/com/trustvault/controller/DocumentController.java#L137)) to prevent HTTP response splitting.
  - **Boundaries:** Controllers contain no business logic, direct database queries, or raw disk operations.

### C. Exception Handling Boundary (`com.trustvault.exception`)
- **Primary Role:** Centralize failure management and prevent information leakage.
- **Responsibilities:**
  - [`GlobalExceptionHandler`](file:///d:/TrustVault/src/main/java/com/trustvault/exception/GlobalExceptionHandler.java) intercepts domain and runtime exceptions (`ResourceNotFoundException`, `AccessDeniedException`, `StorageException`, `StorageFileNotFoundException`, `MethodArgumentNotValidException`, and uncaught `Exception`).
  - Converts errors into sanitized [`ErrorResponseDto`](file:///d:/TrustVault/src/main/java/com/trustvault/dto/ErrorResponseDto.java) objects or standardized web views.
  - Completely strips stack traces, database schema constraints, physical file paths, and internal storage UUIDs from all responses.

### D. Service Layer (`com.trustvault.service`, `com.trustvault.storage`)
- **Primary Role:** Orchestrate business workflows, enforce granular authorization, manage transactions, and coordinate audit logging.
- **Responsibilities:**
  - Verify caller authorization via [`DocumentAuthorizationService`](file:///d:/TrustVault/src/main/java/com/trustvault/service/DocumentAuthorizationService.java) before any data is read or written.
  - Execute file structure, MIME type, and decompression safety checks via [`FileValidationService`](file:///d:/TrustVault/src/main/java/com/trustvault/storage/FileValidationService.java).
  - Manage transactional boundaries (`@Transactional`) ensuring atomic rollbacks upon failure.
  - Dispatch audit events via [`AuditService`](file:///d:/TrustVault/src/main/java/com/trustvault/service/AuditService.java) with appropriate propagation strategies.

### E. Repository Layer (`com.trustvault.repository`)
- **Primary Role:** Provide safe, parameterized persistence operations over PostgreSQL.
- **Responsibilities:**
  - Use Spring Data JPA derived queries and typed JPQL to completely eliminate SQL injection risks.
  - Provide isolated entity access for users, documents, document shares, and audit events.
  - Contain no business logic or file I/O operations.

### F. Storage Subsystem (`com.trustvault.storage`)
- **Primary Role:** Provide isolated, tamper-evident private blob persistence via the pluggable [`StorageService`](file:///d:/TrustVault/src/main/java/com/trustvault/storage/StorageService.java) interface.
- **Implementations:**
  - **[`LocalStorageService`](file:///d:/TrustVault/src/main/java/com/trustvault/storage/LocalStorageService.java) (`trustvault.storage.provider=local`):**
    - Isolates files in a configured private directory (`./private-storage/uploads`), completely outside public web roots.
    - Assigns randomly generated UUID storage keys to stored files (`{storageKey}.bin`), eliminating client-controlled file paths.
    - Rejects symbolic links (`LinkOption.NOFOLLOW_LINKS`) and validates canonical path containment to prevent path traversal attacks.
    - Employs atomic staging (`.tmp` to `.bin`) to eliminate partial writes.
  - **[`ConvexStorageService`](file:///d:/TrustVault/src/main/java/com/trustvault/storage/ConvexStorageService.java) (`trustvault.storage.provider=convex`):**
    - Communicates exclusively over secure HTTPS endpoints with deployed Convex HTTP Actions (`/health`, `/files/{storageKey}`).
    - Authenticates via Bearer token authorization using `TRUSTVAULT_CONVEX_SHARED_SECRET`.
    - Implements robust validation against accidental shell assignment expressions while supporting standard Base64 secrets with padding (`=`).
    - Enforces client-side 10 MiB upload caps and sanitizes diagnostic logs to prevent credential leakage.
    - Prevents ephemeral Render container data loss by persisting production blobs durably in Convex cloud storage.

---

## 3. High-Level Request & Data Flows

### A. Document Creation & Viewing Flow
```
User Request (GET /documents/{id})
       │
       ▼
Spring Security ────► Authenticates Principal
       │
       ▼
DocumentController ──► Calls DocumentService.getDocument(id, username)
       │
       ▼
DocumentAuthorizationService ──► Checks Owner OR Active Share (READ/EDIT)
       │
       ├─► [Unauthorized / Unshared] ──► Throws ResourceNotFoundException (HTTP 404)
       │
       └─► [Authorized] ───────────────► Loads Document & Collaborator List
                                         │
                                         ▼
                             Renders templates/documents/detail.html
                             (Contextual action controls based on role)
```

### B. Secure File Upload Flow
```
Client POST /api/documents/{id}/file (Multipart file payload + CSRF)
       │
       ▼
Spring Security ────► Validates CSRF Token & Authentication Context
       │
       ▼
DocumentFileUploadController ──► Calls DocumentService.uploadFile(id, file, username)
       │
       ▼
DocumentAuthorizationService ──► Enforces SharePermission.EDIT (Owner or EDIT collaborator)
       │
       ▼
FileValidationService ─────────► Enforces size <= 10 MiB
                                 Inspects magic bytes (PDF, PNG, JPEG, ZIP)
                                 Validates UTF-8 encoding & rejects NUL bytes (0x00)
                                 Validates Zip entries (max 1000 files, 50 MiB, Zip-Slip check)
                                 Computes SHA-256 digest
       │
       ▼
LocalStorageService ───────────► Stages file atomically in ./private-storage/uploads/{UUID}.bin
       │
       ▼
DocumentRepository ────────────► Updates metadata (filename, content_type, size, checksum, storageKey)
       │
       ▼
AuditService ──────────────────► Records FILE_UPLOAD event (Propagation.REQUIRED)
       │
       ▼
Returns HTTP 200 OK (DocumentDto)
```

### C. Secure File Download & Verification Flow
```
Client GET /api/documents/{id}/file
       │
       ▼
Spring Security ────► Authenticates Principal
       │
       ▼
DocumentFileDownloadController ──► Calls DocumentService.downloadFile(id, username)
       │
       ▼
DocumentAuthorizationService ────► Enforces SharePermission.READ (Owner or any collaborator)
       │
       ▼
LocalStorageService ─────────────► Streams bytes from ./private-storage/uploads/{UUID}.bin
       │
       ▼
FileValidationService ───────────► Calculates streaming SHA-256 digest
       │
       ▼
Integrity Check ─────────────────► MessageDigest.isEqual(computedSha256, document.fileChecksum)
       │
       ├─► [MISMATCH] ───────────► Throws StorageException (Fail-Closed, HTTP 500, 0 bytes sent)
       │
       └─► [MATCH] ──────────────► AuditService records FILE_DOWNLOAD (Propagation.REQUIRED)
                                   DocumentController sanitizes Content-Disposition header
                                   Streams Resource with X-Content-Type-Options: nosniff
```

---

## 4. Authentication, Session Management & Security Controls

TrustVault implements a hardened session-based authentication model configured in [`SecurityConfig.java`](file:///d:/TrustVault/src/main/java/com/trustvault/security/SecurityConfig.java):

### A. Password Security & Form Login
- Passwords are encrypted using Spring Security's `BCryptPasswordEncoder` configured with work factor 12.
- Authenticated via standard form login with credentials verified against PostgreSQL `users` table.
- Development-only credential initialization (`DevUserInitializer`) and one-shot password reset runners (`DevPasswordResetRunner`) require explicit opt-in properties (`TV_DEV_SEED_ENABLED=true`, `TV_DEV_RESET_PASSWORD=true`), run only under the `dev` profile, and never print or log plaintext credentials.

### B. Session Fixation Defense
- Configured via `.sessionFixation(fixation -> fixation.changeSessionId())`. Upon successful login, Spring Security assigns a new HTTP session ID while migrating existing session attributes, mitigating session fixation attacks.

### C. Cross-Site Request Forgery (CSRF) Protection
- Synchronizer Token Pattern CSRF protection is active globally across all state-mutating HTTP methods (`POST`, `PUT`, `DELETE`).
- Server-rendered Thymeleaf forms automatically include hidden `_csrf` tokens.
- REST endpoints accept CSRF tokens via standard form parameters or the `X-CSRF-TOKEN` header.

### D. Secure Logout Architecture
- Handled exclusively via `POST /logout` requiring a valid CSRF token.
- Executed by Spring Security's `SecurityContextLogoutHandler`:
  - Invalidates the active `HttpSession`.
  - Clears the thread-local `SecurityContext`.
  - Expunges the `JSESSIONID` cookie by returning `Set-Cookie: JSESSIONID=; Path=/; Max-Age=0; HttpOnly`.
  - Redirects the user to `/login?logout`.
- The shared UI navbar integrates a CSRF-protected POST logout form.

### E. Session Tracking & Transaction-Safe Revocation
- Inbound requests pass through `ConcurrentSessionFilter` using a registered `SessionRegistryImpl`.
- When an account is deactivated (`UserService.deactivateUser`) or credentials change (`UserService.changePassword`), active sessions are revoked.
- **Transaction-Safe Hook:** Revocation is scheduled post-commit using `TransactionSynchronizationManager.registerSynchronization` with an `afterCommit()` callback. Sessions are expired only after the database update commits, preventing premature session invalidation if a transaction rolls back.

### F. Administrator Account Provisioning Architecture (Local Dev vs. Production)
TrustVault distinguishes between local development test scaffolding and production account management to maintain defense-in-depth:

1. **Local Development Seeding (`DevUserInitializer`):**
   - **Gated Execution:** Restricted to the `dev` Spring profile and requiring `trustvault.dev.seed-user.enabled=true` (`TV_DEV_SEED_ENABLED=true`). It is absent from the container in production.
   - **Role Parameterization:** Resolves `TV_DEV_ROLE` (or `trustvault.dev.seed-user.role`), defaulting to `ROLE_USER`. When set to `ROLE_ADMIN`, assigns the administrator role safely via `UserService.createUser(...)`.
   - **Role Validation:** Strictly validated against the `Role` enum (`ROLE_USER`, `ROLE_ADMIN`). Unsupported or unapproved roles throw an exception and abort startup before any record is created.
   - **Idempotency & Conflict Protection:** If a username or email conflict exists, creation is skipped, strictly preserving existing account credentials and roles.

2. **Production Cloud Environment (Render / Neon Cloud PostgreSQL):**
   - **Zero Public Registration / Self-Elevation Routes:** TrustVault does not expose public user registration or role modification endpoints.
   - **Direct Authenticated Database Administration:** The initial administrator account (day-zero provisioning) or subsequent account elevations are performed directly against the Neon database by an authorized database administrator over TLS (`sslmode=require`).
   - **Offline BCrypt Hashing (`PasswordHashGenerator`):** Passwords are encrypted offline with `BCryptPasswordEncoder` (work factor 12) via a dedicated CLI utility (`PasswordHashGenerator`) before SQL insertion, ensuring plaintext passwords are never transmitted, committed, or recorded in shell command histories.
   - **Admin Zero-Trust Boundary:** Holding `ROLE_ADMIN` allows access to global audit trails (`/audit`), but upholds zero-trust regarding document payloads. Document authorization rules (`DocumentAuthorizationService`) apply equally to administrators.

---

## 5. Document Authorization & Access Control (ABAC Model)

TrustVault enforces fine-grained Attribute-Based Access Control (ABAC) at the service layer via [`DocumentAuthorizationService`](file:///d:/TrustVault/src/main/java/com/trustvault/service/DocumentAuthorizationService.java).

### A. Access Matrix

| Role / Principal | View Metadata | Download File | Edit Metadata | Upload/Replace File | Delete Document | Manage Collaborators |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Document Owner** | Allowed | Allowed | Allowed | Allowed | Allowed | Allowed |
| **Collaborator (`EDIT`)** | Allowed | Allowed | Allowed | Allowed | **Denied** (403) | **Denied** (403) |
| **Collaborator (`READ`)** | Allowed | Allowed | **Denied** (403) | **Denied** (403) | **Denied** (403) | **Denied** (403) |
| **Unshared User** | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) |
| **Admin (`ROLE_ADMIN`)** | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* |

*\*Note: Unless explicitly granted an ownership or share record.*

### B. Anti-IDOR Information Leakage Reduction
- If an unshared user requests access to a document (or attempts to view, upload, download, share, or delete it), the service throws `ResourceNotFoundException("Document not found with id: " + documentId)`.
- Handled by `GlobalExceptionHandler` to return `HTTP 404 Not Found`.
- **Architectural Rationale:** Returning `404 Not Found` rather than `403 Forbidden` significantly reduces information leakage by preventing unauthorized callers from determining whether an unshared document ID exists on the server.

### C. Admin Zero-Trust Policy
- As implemented in `DocumentAuthorizationService.authorizeDocument`, administrators (`ROLE_ADMIN`) manage system users but have **no implicit document viewing or editing rights**. Private documents remain private unless the owner explicitly shares them with the administrator.

---

## 6. Document-Sharing Architecture & Collaboration Workflow

Collaborator access is modeled through the `DocumentShare` entity, linking a `Document`, a target `User`, and a `SharePermission` (`READ` or `EDIT`).

```
┌──────────────────┐         1:N         ┌───────────────────┐        N:1        ┌──────────────────┐
│     Document     │────────────────────►│   DocumentShare   │◄──────────────────│       User       │
│ - id             │                     │ - permission      │                   │ - id             │
│ - owner (User)   │                     │   (READ / EDIT)   │                   │ - username       │
└──────────────────┘                     └───────────────────┘                   └──────────────────┘
```

### Collaboration Workflow & Controls:
1. **Owner-Only Share Management:** All share operations (`grantAccess`, `revokeAccess`, `listShares` in [`DocumentShareService`](file:///d:/TrustVault/src/main/java/com/trustvault/service/DocumentShareService.java)) execute [`DocumentAuthorizationService.authorizeDocumentForOwner`](file:///d:/TrustVault/src/main/java/com/trustvault/service/DocumentAuthorizationService.java#L247). Non-owners are denied immediately.
2. **REST Endpoints:**
   - `GET /api/documents/{id}/shares`: Lists current active collaborators (Owner only).
   - `POST /api/documents/{id}/shares`: Adds or updates a collaborator permission (Owner only). Requires target username and `READ` or `EDIT` permission. Prevents self-sharing.
   - `DELETE /api/documents/{id}/shares/{targetUsername}`: Revokes collaborator access immediately (Owner only).
3. **Audit Dispatch:** Every share grant (`DOCUMENT_SHARE_ADD`, `DOCUMENT_SHARE_UPDATE`) and revocation (`DOCUMENT_SHARE_REVOKE`) records principal, target username, permission, and document ID in the audit ledger.

---

## 7. Private File Storage & Integrity Verification Subsystem

### A. Storage Architecture
- Files are stored in a dedicated local filesystem directory (`./private-storage/uploads`), kept completely decoupled from web application roots, classpath assets, or static HTTP mappings.
- Direct filesystem filenames use random UUID nonces (`{storageKey}.bin`). The original user-supplied filename is stored exclusively in the database metadata table.

### B. Upload Validation Pipeline
[`FileValidationService`](file:///d:/TrustVault/src/main/java/com/trustvault/storage/FileValidationService.java) executes an exhaustive pre-storage validation sequence:
1. **Size Boundary:** Validates that total bytes do not exceed `10 MiB` (`10_485_760` bytes).
2. **Magic Byte Inspection:** Inspects byte headers to verify signatures:
   - PDF: `%PDF-` (`0x25, 0x50, 0x44, 0x46, 0x2D`)
   - PNG: `0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A`
   - JPEG: `0xFF, 0xD8, 0xFF`
   - ZIP: `PK\x03\x04` (`0x50, 0x4B, 0x03, 0x04`)
3. **Text & Script Validation:** Plaintext documents (`text/plain`, `.txt`, `.csv`, `.md`) are verified for valid UTF-8 encoding and checked for embedded binary NUL bytes (`0x00`), which trigger immediate rejection.
4. **Zip-Slip & Zip-Bomb Defenses:** Inspects zip headers without fully uncompressing the archive:
   - Max 1,000 entries.
   - Max 50 MiB uncompressed size.
   - Compression ratio limits to reject recursive/oversized zip bombs.
   - Canonical entry path verification rejecting directory traversal sequences (`../`, Zip-Slip).

### C. Download Integrity Verification (Pre-Stream Fail-Closed)
- During upload, `FileValidationService.calculateSha256(byte[])` records the hex-encoded digest in `document.file_checksum`.
- During download, [`DocumentService.downloadFile`](file:///d:/TrustVault/src/main/java/com/trustvault/service/DocumentService.java#L464) streams the file through `FileValidationService.calculateSha256(InputStream)` using fixed 8 KiB buffers before transmitting data to the client.
- The computed hash is compared to the database checksum using constant-time comparison (`MessageDigest.isEqual`).
- **Fail-Closed Guarantee:** If the hash mismatches (indicating bitrot or unauthorized file modification on disk), the operation throws a `StorageException`. The response fails with `HTTP 500 Internal Server Error`, and zero file bytes are returned to the client.

---

## 8. Audit Logging Subsystem

Enterprise accountability requires a resilient, tamper-evident record of all security-relevant activity. TrustVault implements this via [`AuditService`](file:///d:/TrustVault/src/main/java/com/trustvault/service/AuditService.java) and the [`AuditEvent`](file:///d:/TrustVault/src/main/java/com/trustvault/entity/AuditEvent.java) entity.

### A. Event Categories & Schema
Events record:
- `timestamp`: UTC timestamp.
- `principal`: Authenticated username (or "ANONYMOUS").
- `action`: Specific action enum (e.g., `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `SECURITY_DENIAL`, `DOCUMENT_CREATE`, `DOCUMENT_READ`, `FILE_UPLOAD`, `FILE_DOWNLOAD`, `DOCUMENT_SHARE_ADD`, `DOCUMENT_SHARE_REVOKE`, `USER_DEACTIVATED`).
- `resourceType` and `resourceId`: Target entity classification and ID.
- `ipAddress` and `userAgent`: Client network origin.
- `details`: Contextual metadata (e.g., target collaborator username, granted permission). Sensitive fields (passwords, tokens, file bytes) are strictly excluded.

### B. Transactional Propagation Strategy
- **Standard Business Events (`recordEvent`):** Configured with `@Transactional(propagation = Propagation.REQUIRED)`. Audit logging participates in the caller's business transaction. If the business transaction fails, the uncommitted audit event is rolled back with it, preventing phantom success records.
- **Security Denial Events (`recordSecurityDenial`):** Configured with `@Transactional(propagation = Propagation.REQUIRES_NEW)`. Denial records run in an autonomous database transaction and commit immediately. Even if the caller's transaction rolls back or throws an exception, the security denial record is permanently retained in the database.

### C. Immutability & Privileged Database Administrator Boundary
- **Application-Level Immutability:** The `AuditEvent` entity defines `@Column(updatable = false)` across its fields and contains no mutator/setter methods. `AuditEventRepository` exposes only append (`save`) and read methods. Application users, services, and web callers cannot modify or delete existing audit events.
- **Architectural Boundary (DBA Distinction):** Immutability is enforced at the **application and JPA layer**. It does **not** prevent a privileged PostgreSQL database administrator or an attacker with direct SQL console credentials from modifying or deleting rows in the `audit_events` table. Full non-repudiation against database administrators requires future database-level write-once controls or external cryptographic log forwarders.

---

## 9. Security Posture Summary & Architectural Boundaries

### Implemented & Verified Controls vs. Residual Risks

| Domain | Implemented & Verified Control | Residual Risk / Deployment Limitation | Companion Reference |
| :--- | :--- | :--- | :--- |
| **Access Control** | Fine-grained ABAC (Owner, EDIT, READ), Anti-IDOR HTTP 404 handling, Admin Zero-Trust. | HTTP 404 reduces information leakage; subtle timing side-channels remain theoretical. | [`THREATS.md § 4.1, 4.2`](file:///d:/TrustVault/THREATS.md#41-broken-object-level-authorization-bola--idor) |
| **File Storage** | Isolated private disk, UUID keys, 10 MiB limit, magic bytes, Zip-Slip/Bomb defenses. | No heuristic anti-malware engine (e.g., ClamAV) for valid container formats. | [`THREATS.md § 4.3, 5.3`](file:///d:/TrustVault/THREATS.md#43-malicious-file-uploads--path-traversal) |
| **File Integrity** | Streaming pre-download SHA-256 validation; constant-time comparison; fail-closed HTTP 500. | Storage files are unencrypted at rest; file security relies on host OS ACLs. | [`THREATS.md § 4.4, 5.4`](file:///d:/TrustVault/THREATS.md#44-file-tampering--integrity-degradation) |
| **Sessions** | BCrypt work factor 12, `changeSessionId` fixation defense, CSRF-protected POST logout. | `SessionRegistryImpl` stores sessions in JVM heap; multi-node clusters require Spring Session Redis. | [`THREATS.md § 4.5, 5.2`](file:///d:/TrustVault/THREATS.md#45-authentication--session-attacks) |
| **Rate Limiting** | Strict file size and zip decompression boundaries prevent single-request memory exhaustion. | No application-level rate limiting on `/login` or API routes; requires upstream reverse proxy. | [`THREATS.md § 4.10, 5.1`](file:///d:/TrustVault/THREATS.md#410-denial-of-service-dos) |
| **Audit Trails** | Autonomous `REQUIRES_NEW` denial logging, JPA entity immutability (`updatable=false`). | Immutability is at application layer; does not restrict a privileged PostgreSQL DBA. | [`THREATS.md § 4.7, 5`](file:///d:/TrustVault/THREATS.md#47-audit-log-tampering--evasion) |
| **Error Handling** | Centralized `GlobalExceptionHandler` strips stack traces and internal paths into sanitized DTOs. | Minimal residual risk; uniform error envelopes applied across all routes. | [`THREATS.md § 4.8`](file:///d:/TrustVault/THREATS.md#48-sensitive-information-disclosure) |

---

## 10. Verification & Test Evidence

The architectural controls described in this blueprint are validated by an automated test suite comprising **331 tests** with 0 failures:
- **Authorization & Anti-IDOR:** `DocumentAuthorizationTest`, `DocumentFileUploadServiceTest`
- **Sharing & Permission Enforcement:** `DocumentShareRestControllerTest`
- **File Validation & Safety:** `FileValidationServiceTest` (50 tests), `LocalStorageServiceTest` (23 tests)
- **Upload & Download Operations:** `DocumentFileUploadControllerTest`, `DocumentFileDownloadControllerTest` (14 tests)
- **Authentication, Logout & Session Management:** `AuthenticationIntegrationTest`, `LogoutIntegrationTest`, `UserServiceSessionInvalidationTest`
- **Audit Logging & Transaction Propagation:** `BusinessAuditIntegrationTest`, `AuditEventPersistenceTest`
- **Error Sanitization:** `GlobalExceptionHandlerTest`
