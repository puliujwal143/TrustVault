# TrustVault — Secure Enterprise Document-Sharing Application

TrustVault is an enterprise document-sharing platform engineered with defense-in-depth principles. It combines fine-grained Attribute-Based Access Control (ABAC), isolated private document storage, cryptographic file integrity verification, and an auditable activity history.

For in-depth architectural blueprints and component breakdowns, see [`ARCHITECTURE.md`](file:///d:/TrustVault/ARCHITECTURE.md).
For detailed threat models, risk ratings, and security verification checklists, see [`THREATS.md`](file:///d:/TrustVault/THREATS.md).

---

## 1. Technology Stack

TrustVault is built using a modern enterprise Java stack:

- **Runtime & Language:** Java 21 (LTS)
- **Framework:** Spring Boot 3.3.5
- **Security:** Spring Security 6 (Form Login, Synchronizer Token CSRF, Session Fixation Migration, Concurrent Session Tracking)
- **Web & UI:** Spring Web MVC with Thymeleaf 3 and Spring Security Layout Dialect
- **Persistence:** Spring Data JPA & Hibernate with PostgreSQL Dialect
- **Database:** PostgreSQL 15+ (Production / Local Dev), H2 in PostgreSQL compatibility mode (Isolated test suite)
- **Storage Subsystem:** Local filesystem storage decoupled from web document roots
- **Validation:** Jakarta / Hibernate Bean Validation & custom byte-level file payload inspection
- **Build & Dependency Tooling:** Apache Maven with Maven Wrapper (`mvnw` / `mvnw.cmd`)
- **Testing Suite:** JUnit 5, MockMvc, Spring Security Test, AssertJ

---

## 2. Core Features & Access Control Model

### Authentication & Account Security
- **Hardened Passwords:** Password hashes are computed with Spring Security's `BCryptPasswordEncoder` using work factor 12.
- **Session Fixation Defense:** Issues a new HTTP session ID upon authentication (`changeSessionId()`) while migrating existing attributes.
- **CSRF-Protected Logout:** Handled exclusively via `POST /logout` requiring a valid CSRF token, invalidating the session, clearing the `SecurityContext`, and expiring the `JSESSIONID` cookie (`Max-Age=0`).
- **Transaction-Safe Session Invalidation:** When accounts are deactivated or credentials reset, sessions are revoked post-commit via `SessionRegistry` and `TransactionSynchronizationManager.afterCommit()`.

### Document Access & Collaboration Boundaries
TrustVault enforces Attribute-Based Access Control (ABAC) at the service layer:

| Role / Principal | View Metadata | Download File | Edit Metadata | Upload/Replace File | Delete Document | Manage Collaborators |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Document Owner** | Allowed | Allowed | Allowed | Allowed | Allowed | Allowed |
| **Collaborator (`EDIT`)** | Allowed | Allowed | Allowed | Allowed | **Denied** (403) | **Denied** (403) |
| **Collaborator (`READ`)** | Allowed | Allowed | **Denied** (403) | **Denied** (403) | **Denied** (403) | **Denied** (403) |
| **Unshared User** | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) |
| **Admin (`ROLE_ADMIN`)** | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* |

*\*Note: Unless explicitly granted an ownership or share record (Admin Zero-Trust Policy).*

- **Anti-IDOR Information Leakage Reduction:** Unshared documents return `HTTP 404 Not Found` (`ResourceNotFoundException`) rather than `403 Forbidden`, preventing attackers from easily enumerating valid document IDs.
- **Owner-Only Share Management:** Document owners manage collaborators via the document detail page or REST endpoints (`POST/DELETE/GET /api/documents/{id}/shares/**`). Collaborators cannot modify sharing rules or delete documents.

### Secure File Upload, Storage & Download
- **10 MiB File Boundary:** `FileValidationService` strictly caps file uploads to 10 MiB (`10_485_760` bytes).
- **Deep Payload Validation:** Verifies magic byte signatures for PDF (`%PDF-`), PNG, JPEG, and ZIP. Plaintext/code files are verified for UTF-8 encoding and immediately rejected if binary NUL bytes (`0x00`) are present.
- **Zip-Slip & Zip-Bomb Defenses:** Inspects zip entries without full decompression, enforcing entry limits (max 1,000 files), decompression thresholds (max 50 MiB), and blocking path traversal sequences (`../`).
- **Isolated Private Storage:** `LocalStorageService` stores files in `./private-storage/uploads` using non-predictable UUID keys (`{storageKey}.bin`), rejecting symlinks (`NOFOLLOW_LINKS`) and preventing directory traversal.
- **Download Integrity Verification (Fail-Closed):** Before streaming a download, `DocumentService.downloadFile` computes the streaming SHA-256 digest from disk and compares it to the database checksum using constant-time `MessageDigest.isEqual`. A mismatch immediately aborts the request (`StorageException`, `HTTP 500`), returning zero bytes to protect clients from corrupted or altered files.
- **Header Injection Defense:** Filenames in the `Content-Disposition` header are sanitized to remove carriage returns, newlines, semicolons, and quotes.

### Auditable Activity History
- **Autonomous Denial Logging:** Security denials are recorded using `@Transactional(propagation = Propagation.REQUIRES_NEW)`, ensuring denial records persist in the database even when the caller's transaction rolls back.
- **Transactional Consistency for Business Events:** Standard audit events use `Propagation.REQUIRED`, rolling back if the business transaction fails to prevent phantom success logs.
- **Application-Level Immutability:** The `AuditEvent` entity defines `@Column(updatable = false)` and exposes no setters; `AuditEventRepository` allows append and read operations only.
- **Sensitive Data Hygiene:** Passwords, tokens, and raw file payloads are never stored in audit records.

---

## 3. Prerequisites

1. **Java Development Kit (JDK):** Java 21 or higher.
   Verify installation:
   ```powershell
   java -version
   # Expected output: openjdk version "21.x.x" ...
   ```
2. **PostgreSQL Database:** PostgreSQL 15+ running locally or accessible via network.
3. **Build Tool:** **No global Maven installation is required.** The included Maven Wrapper (`mvnw.cmd` on Windows, `./mvnw` on Unix) executes all build and test tasks.

---

## 4. Local Setup & Running (Windows PowerShell)

### Step 1: PostgreSQL Database Setup
Create a PostgreSQL database for TrustVault without hardcoding passwords into source files:

1. Connect to PostgreSQL via `psql`:
   ```powershell
   psql -U postgres
   ```
2. Create the database:
   ```sql
   CREATE DATABASE trustvault;
   \q
   ```
3. Initialize the database schema:
   By default, `application.yml` specifies `jpa.hibernate.ddl-auto: validate`. Execute the bundled schema script against your database:
   ```powershell
   psql -U postgres -d trustvault -f src/main/resources/schema.sql
   ```
   *(Alternatively, set `JPA_DDL_AUTO=update` in your `.env` file during initial development).*

### Step 2: Configure Environment Variables
Copy `.env.example` to `.env` in the project root:

```powershell
Copy-Item .env.example .env
```

Configure your local database credentials and server settings in `.env`:

```ini
DB_HOST=localhost
DB_PORT=5432
DB_NAME=trustvault
DB_USERNAME=postgres
DB_PASSWORD=your_secure_password_here

PORT=8080
STORAGE_UPLOAD_DIR=./private-storage/uploads
```

### Step 3: Development User Provisioning (Optional)
To seed an initial test user on startup without hardcoding credentials in code:
1. Ensure the `dev` profile is active.
2. Set the following environment variables in your shell or `.env`:
   ```powershell
   $env:TV_DEV_SEED_ENABLED="true"
   $env:TV_DEV_USERNAME="devuser"
   $env:TV_DEV_PASSWORD="YourStrongDevPassword123!"
   $env:TV_DEV_EMAIL="devuser@example.com"
   ```
   *Note: `DevUserInitializer` only executes when both the `dev` profile is enabled and `TV_DEV_SEED_ENABLED=true`.*

### Step 4: Port Configuration & Overrides
- **Default Port:** The application starts on port `8080` (configured as `server.port: ${PORT:8080}`).
- **Resolving Port Conflicts:** If port 8080 is occupied by another local service, override the port without altering configuration files:
  - Via environment variable:
    ```powershell
    $env:PORT="8081"
    .\mvnw.cmd spring-boot:run
    ```
  - Or via command-line argument:
    ```powershell
    .\mvnw.cmd spring-boot:run -Dspring-boot.run.arguments="--server.port=8081"
    ```

### Step 5: Start the Application
Run the application using the Maven Wrapper:

```powershell
.\mvnw.cmd spring-boot:run
```

Once started, access TrustVault in your browser:
- **Application UI:** `http://localhost:8080/` (redirects to `/login`)
- **Health Check Endpoint:** `http://localhost:8080/api/health`

---

## 5. Running Automated Tests

TrustVault includes a comprehensive unit and integration test suite. Automated tests execute hermetically using an in-memory H2 database (configured in PostgreSQL compatibility mode) and isolated test file storage (`./target/test-storage`), requiring no running PostgreSQL instance.

To run the entire test suite on Windows:

```powershell
.\mvnw.cmd clean test
```

### Test Suite Execution Summary
- **Verified Full Test Suite Result:** **368 tests run, 368 passed, 0 failures, 0 errors, 6 skipped.**
- **Skipped Tests:** 6 tests in `LocalStorageServiceTest` verify symbolic link rejection on Unix file systems. On Windows environments without Developer Mode / administrative symlink privileges, these tests are cleanly skipped via JUnit assumptions.

To run a specific test suite:

```powershell
# Comprehensive Security Authorization Matrix (All Boundaries)
.\mvnw.cmd test -Dtest=SecurityMatrixAuthorizationTest

# Document Authorization & Anti-IDOR Tests
.\mvnw.cmd test -Dtest=DocumentAuthorizationTest

# Document Controller REST API Tests
.\mvnw.cmd test -Dtest=DocumentRestControllerTest

# Document Web UI & Search/Filter Tests
.\mvnw.cmd test -Dtest=DocumentViewControllerTest

# File Download & Checksum Verification Tests
.\mvnw.cmd test -Dtest=DocumentFileDownloadControllerTest

# File Validation & Zip Security Tests
.\mvnw.cmd test -Dtest=FileValidationServiceTest
```

---

## 6. Project Structure

```text
TrustVault/
├── .mvn/wrapper/                  # Maven Wrapper scripts and configuration
├── src/
│   ├── main/
│   │   ├── java/com/trustvault/
│   │   │   ├── audit/             # Audit action enums and event listeners
│   │   │   ├── config/            # Dev seed & password reset runners
│   │   │   ├── controller/        # Web view & REST API controllers
│   │   │   ├── dto/               # API contract DTOs (Document, Share, ErrorResponse)
│   │   │   ├── entity/            # JPA entities (User, Document, DocumentShare, AuditEvent)
│   │   │   ├── exception/         # Centralized GlobalExceptionHandler
│   │   │   ├── repository/        # Spring Data JPA repositories
│   │   │   ├── security/          # SecurityConfig, CustomUserDetailsService
│   │   │   ├── service/           # Authorization, Document, Share, User, Audit services
│   │   │   ├── storage/           # LocalStorageService, FileValidationService
│   │   │   └── TrustVaultApplication.java  # Main application entry point
│   │   └── resources/
│   │       ├── application.yml    # Environment-driven application configuration
│   │       ├── schema.sql         # Idempotent PostgreSQL DDL schema
│   │       ├── static/            # Static assets (CSS styles, client scripts)
│   │       └── templates/         # Thymeleaf server-rendered HTML views
│   └── test/
│       ├── java/com/trustvault/   # 13 verified test suites covering all layers
│       └── resources/
│           └── application.properties # Isolated H2 test database configuration
├── .env.example                   # Environment configuration template
├── ARCHITECTURE.md                # Detailed architectural design & request flows
├── THREATS.md                     # Comprehensive threat model & risk analysis
├── mvnw / mvnw.cmd                # Maven Wrapper executables
├── pom.xml                        # Maven project descriptor
└── README.md                      # Project documentation
```

---

## 7. Residual Risks & Architectural Boundaries

While all implemented security features have been verified against active tests, the following operational and architectural boundaries apply:

1. **No Application-Level Rate Limiting:** The application does not currently implement in-code request throttling on `/login` or file endpoints. In production, an upstream reverse proxy (e.g., Nginx) or WAF should enforce rate limits against brute-force attempts.
2. **In-Memory `SessionRegistry` Scalability Limitation:** Active sessions are tracked within local JVM heap memory (`SessionRegistryImpl`). In a horizontally scaled multi-node deployment, session invalidation across instances requires Spring Session with Redis.
3. **No Antivirus / Heuristic Malware Scanning:** `FileValidationService` inspects file signatures, magic bytes, and archive structures, but does not execute heuristic anti-malware analysis (e.g., ClamAV) for malicious embedded active content in valid file containers.
4. **Unencrypted File Storage at Rest:** Stored file blobs in `./private-storage/uploads` rely on host operating system file access controls rather than application-layer transparent encryption (e.g., AES-256 GCM).
5. **Database Administrator Boundary:** Audit log immutability is enforced at the **application and JPA layer**. It does not prevent a privileged PostgreSQL database administrator with direct SQL console access from modifying rows.

For complete risk assessments and prioritized remediation plans, consult [`THREATS.md`](file:///d:/TrustVault/THREATS.md).
