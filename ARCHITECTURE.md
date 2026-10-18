# TrustVault — Architecture & Security Blueprint

This document explains the architectural principles, component responsibilities, and security design for **TrustVault**. It serves as an architectural reference and interview preparation guide.

---

## 1. Architectural Overview & Layered Design

TrustVault adheres to a clean, multi-layered enterprise architecture. Each layer maintains a single, well-defined responsibility with strict unidirectional dependencies:

```
[ HTTP Request ]
       │
       ▼
┌──────────────────────────────────────┐
│       Spring Security Filters        │  Authentication & Request Interception
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│          Controller Layer            │  HTTP Handling, Validation, DTO Mapping
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│           Service Layer              │  Business Logic, Authorization Checks,
│                                      │  Transactions, Audit Event Dispatch
└─────────┬──────────────────┬─────────┘
          │                  │
          ▼                  ▼
┌──────────────────┐  ┌──────────────────┐
│ Repository Layer │  │ Storage Engine   │  Persistent State &
│ (Spring Data JPA)│  │ (Private Disk)   │  Secure Blob Management
└──────────────────┘  └──────────────────┘
```

---

## 2. Component Responsibilities

### A. Controllers (`com.trustvault.controller`)
- **Primary Role**: Act as the application's presentation and API boundary.
- **Responsibilities**:
  - Map HTTP routes (`@GetMapping`, `@PostMapping`, etc.) to handler methods.
  - Enforce contract-level validation on incoming payloads via `@Valid` and Bean Validation annotations.
  - Return strongly-typed response envelopes (`ResponseEntity<T>`) with appropriate HTTP status codes (e.g., `200 OK`, `201 Created`).
  - **Boundaries**: Controllers must **never** interact directly with the database, execute raw business logic, or access disk storage directly. All operations are delegated to services.

### B. Services (`com.trustvault.service`)
- **Primary Role**: Orchestrate business logic and manage transactional boundaries.
- **Responsibilities**:
  - Enforce application policies and business rules.
  - Manage database transaction lifecycles using `@Transactional`.
  - Coordinate data mutations across repositories, private file storage, and audit logging.
  - Verify that the calling principal possesses the necessary rights before proceeding.
  - **Boundaries**: Services are decoupled from HTTP constructs (such as `HttpServletRequest` or `HttpServletResponse`).

### C. Repositories (`com.trustvault.repository`)
- **Primary Role**: Provide isolated, secure data persistence abstractions.
- **Responsibilities**:
  - Extend Spring Data JPA interfaces (`JpaRepository`, `CrudRepository`).
  - Use parameterized queries and Spring Data method derivation to completely prevent SQL injection.
  - Scope queries to authenticated user/tenant contexts where appropriate.
  - **Boundaries**: Repositories deal solely with entity persistence and querying; they never handle business workflows or file I/O.

---

## 3. Document Authorization Strategy

> **Status Notice**: Document-level authorization is **not implemented in Phase 1**. Phase 1 establishes the baseline security foundation (all endpoints require authentication except `/api/health`).

### Planned Design for Phase 2+:
- **Dual-Layer Access Control**:
  - **Role-Based Access Control (RBAC)**: Baseline roles (`USER`, `AUDITOR`, `ADMIN`) define coarse operational privileges.
  - **Attribute-Based / Document-Level Access Control (ABAC)**: Every document will have an explicit ownership and sharing matrix.
- **Enforcement Point**: Authorization checks must occur **inside the Service layer** (e.g., via `@PreAuthorize("@documentSecurity.canAccess(principal, #documentId)")` or programmatic evaluation) before any metadata is retrieved or file bytes are read.
- **Denial Pattern**: If a user requests a document they do not have permission to view, the system will return `403 Forbidden` (or `404 Not Found` if metadata disclosure must be prevented).

---

## 4. Private File Storage Architecture

### Why Public Static Directories Are Strictly Prohibited
- In standard web applications, files placed in `src/main/resources/static`, `src/main/resources/public`, or web server document roots can be downloaded by anyone who guesses or discovers the URL, bypassing authentication and authorization entirely.
- Exposing documents statically creates severe vulnerabilities:
  - Unauthorized direct access.
  - Inability to verify user permissions per request.
  - Inability to record audit access logs on file downloads.

### TrustVault's Secure Storage Model
1. **Isolated Filesystem Location**: Uploaded documents are stored outside the web root (configured via `STORAGE_UPLOAD_DIR`, defaulting to `./private-storage/uploads`).
2. **Identifier Obfuscation**: Files on disk are named using non-predictable UUIDs rather than original user filenames, preventing Directory Traversal attacks (`../../etc/passwd`).
3. **Controlled Streaming**: Files are retrieved exclusively through an authenticated Spring Boot streaming endpoint that checks authorization, reads the file from private disk, and streams the content with secure HTTP headers (`Content-Disposition: attachment; filename="..."`, `X-Content-Type-Options: nosniff`).

---

## 5. Audit Logging Architecture

Enterprise security and regulatory compliance require a tamper-resistant record of all sensitive operations.

### Core Audit Principles:
1. **Non-Bypassable**: Audit event emission is wired into the service layer lifecycle, ensuring events trigger on both successful and unauthorized attempts.
2. **Structured Event Schema**:
   - **Timestamp**: UTC timestamp of event occurrence.
   - **Principal**: Authenticated username/ID of the actor.
   - **Action**: Discrete verb (`DOCUMENT_UPLOAD`, `DOCUMENT_READ`, `DOCUMENT_SHARE`, `SHARE_REVOKE`, `LOGIN_ATTEMPT`).
   - **Target Resource**: Identifier of the target entity (e.g., document UUID).
   - **Client IP & User-Agent**: Network origin of the request.
   - **Outcome**: `SUCCESS`, `DENIED`, or `ERROR`.
3. **Immutability**: Audit log records must be append-only with no modification or deletion privileges granted to regular application accounts.

---

## 6. Phase 1 Security Baseline Summary

| Security Requirement | Status in Phase 1 | Implementation Mechanism |
| :--- | :--- | :--- |
| Spring Security globally enabled | **Active** | `SecurityConfig` requires authentication on `anyRequest()` |
| Health check accessibility | **Permitted** | Whitelisted `/api/health` without authentication |
| Protected route enforcement | **Enforced** | Tested via `HealthControllerTest` verifying `401 Unauthorized` |
| No hardcoded credentials | **Enforced** | All database connection settings read from environment variables |
| No static document exposure | **Enforced** | No static upload mapping; private storage path configured |
| Exception sanitization | **Enforced** | `GlobalExceptionHandler` strips stack traces from client responses |
| Document-level authorization | **Deferred** | Explicitly scoped for subsequent phases |
