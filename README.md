# TrustVault — Secure Enterprise Document-Sharing Application

TrustVault is an enterprise document-sharing platform engineered with defense-in-depth principles. It combines fine-grained Attribute-Based Access Control (ABAC), isolated private document storage (supporting local filesystem and Convex cloud storage), cryptographic file integrity verification, and an auditable activity history.

- **Live Deployment:** [https://trustvault-axea.onrender.com](https://trustvault-axea.onrender.com)
- **Repository:** https://github.com/puliujwal143/TrustVault

For in-depth architectural blueprints and component breakdowns, see [`ARCHITECTURE.md`](file:///d:/TrustVault/ARCHITECTURE.md).
For detailed threat models, risk ratings, and security verification checklists, see [`THREATS.md`](file:///d:/TrustVault/THREATS.md).

---

## Demo Login Credentials

**Live Application:** https://trustvault-axea.onrender.com

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin@123` |
| Developer | `devuser` | `Devuser@123` |
| Test User | `testuser2` | `Testuser2@123` |

These credentials are for demo and evaluation purposes only. Do not upload personal or confidential documents.

## 1. Technology Stack

TrustVault is built using a modern enterprise Java stack:

- **Runtime & Language:** Java 21 (LTS)
- **Framework:** Spring Boot 3.3.5
- **Security:** Spring Security 6 (Form Login, Synchronizer Token CSRF, Session Fixation Migration, Concurrent Session Tracking)
- **Web & UI:** Spring Web MVC with Thymeleaf 3 and Spring Security Layout Dialect
- **Persistence:** Spring Data JPA & Hibernate with PostgreSQL Dialect
- **Database:** PostgreSQL 15+ / Neon Cloud PostgreSQL (Production / Local Dev), H2 in PostgreSQL compatibility mode (Isolated test suite)
- **Storage Subsystem:** Pluggable `StorageService` provider abstraction:
  - `LocalStorageService`: Local private filesystem storage isolated outside web document roots
  - `ConvexStorageService`: Production cloud storage via Convex HTTP Actions with Bearer token authentication
- **Validation:** Jakarta / Hibernate Bean Validation & custom byte-level file payload inspection
- **Deployment & Runtime:** Multi-stage Docker containerization on Render with non-root security execution
- **Build & Dependency Tooling:** Apache Maven with Maven Wrapper (`mvnw` / `mvnw.cmd`)
- **Testing Suite:** JUnit 5, MockMvc, Spring Security Test, AssertJ

---

## 2. Core Features & Access Control Model

### Three Clearly Defined Access Concepts
TrustVault implements a clean separation between global system administration and document-level attribute-based access control:

1. **Admin (`ROLE_ADMIN`):**
   - Authorized platform and user administrator.
   - Manages user lifecycle, reviews comprehensive audit trails, and monitors system health.
   - **Admin Zero-Trust Policy:** Administrators are NOT automatically granted access to private document contents or file payloads. Access to documents strictly requires an explicit document ownership or share grant.
2. **Document Owner (`document.getOwner()`):**
   - The creator and authoritative custodian of a document.
   - Holds full operational authority: view metadata, download files, edit metadata, upload/replace files, delete documents, and manage collaborators (grant/revoke).
3. **Viewer / Collaborator (`DocumentShare` Grants):**
   - **Viewer (`SharePermission.READ`):** Explicitly authorized user permitted to view document metadata and download attached file payloads. Strictly forbidden from modifying metadata, replacing files, deleting, or managing shares.
   - **Editor (`SharePermission.EDIT`):** Authorized collaborator permitted to view metadata, download files, update metadata, and upload/replace file attachments. Strictly forbidden from deleting the document or managing collaborators.

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
| **Viewer (`READ`)** | Allowed | Allowed | **Denied** (403) | **Denied** (403) | **Denied** (403) | **Denied** (403) |
| **Unshared User** | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) | **Denied** (404) |
| **Admin (`ROLE_ADMIN`)** | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* | **Denied** (404)* |

*\*Note: Unless explicitly granted an ownership or share record (Admin Zero-Trust Policy).*

- **Anti-IDOR Information Leakage Reduction:** Unshared documents return `HTTP 404 Not Found` (`ResourceNotFoundException`) rather than `403 Forbidden`, preventing attackers from easily enumerating valid document IDs.
- **Owner-Only Share Management:** Document owners manage collaborators via the document detail page or REST endpoints (`POST/DELETE/GET /api/documents/{id}/shares/**`). Collaborators cannot modify sharing rules or delete documents.

### Document Categorization & Multi-Parameter Search
- **Document Categorization:** Documents support an optional `category` metadata field (bounded to 50 characters, trimmed, and normalized). Categories can be set at creation and updated during editing by document owners and EDIT collaborators.
- **Multi-Parameter Search:** Users can filter their documents simultaneously across:
  1. **Document Name / Title & Description (`q`):** Full case-insensitive keyword search.
  2. **Document Owner (`owner`):** Filter by creator username.
  3. **Document Category (`category`):** Filter by category with datalist auto-completion for accessible categories.
  4. **Creation Date Range (`fromDate`, `toDate`):** Inclusive date bounding.
- **Cross-User Search Isolation:** Search filters are strictly scoped to documents the requesting user is authorized to access (owned or explicitly shared). Unauthorized or private documents belonging to other users are never evaluated, enumerated, or leaked in search results.

### Secure File Upload, Storage & Download
- **10 MiB File Boundary:** `FileValidationService` strictly caps file uploads to 10 MiB (`10_485_760` bytes).
- **Deep Payload Validation:** Verifies magic byte signatures for PDF (`%PDF-`), PNG, JPEG, and ZIP. Plaintext/code files are verified for UTF-8 encoding and immediately rejected if binary NUL bytes (`0x00`) are present.
- **Zip-Slip & Zip-Bomb Defenses:** Inspects zip entries without full decompression, enforcing entry limits (max 1,000 files), decompression thresholds (max 50 MiB), and blocking path traversal sequences (`../`).
- **Isolated Private Storage:** `LocalStorageService` stores files in `./private-storage/uploads` using non-predictable UUID keys (`{storageKey}.bin`), rejecting symlinks (`NOFOLLOW_LINKS`) and preventing directory traversal.
- **Production Cloud Storage:** `ConvexStorageService` provides seamless, durable cloud blob storage via Convex HTTP Actions over TLS with safe Bearer token authorization, avoiding ephemeral Render container filesystem data loss.
- **Download Integrity Verification (Fail-Closed):** Before streaming a download, `DocumentService.downloadFile` computes the streaming SHA-256 digest and compares it to the database checksum using constant-time `MessageDigest.isEqual`. A mismatch immediately aborts the request (`StorageException`, `HTTP 500`), returning zero bytes to protect clients from corrupted or altered files.
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

# Storage Provider Configuration: 'local' (default) or 'convex' (cloud)
TRUSTVAULT_STORAGE_PROVIDER=local
STORAGE_UPLOAD_DIR=./private-storage/uploads

# Convex Cloud Storage (Required when TRUSTVAULT_STORAGE_PROVIDER=convex)
TRUSTVAULT_CONVEX_BASE_URL=https://your-deployment.convex.site
TRUSTVAULT_CONVEX_SHARED_SECRET=your_convex_shared_secret
```

### Step 3: Development Account Provisioning (Local Only)
To seed an initial test user or administrator on startup in development without hardcoding credentials in code:
1. Ensure the `dev` profile is active (`-Dspring.profiles.active=dev` or `$env:SPRING_PROFILES_ACTIVE="dev"`).
2. Set the following environment variables in your shell or `.env`:
   ```powershell
   $env:TV_DEV_SEED_ENABLED="true"
   $env:TV_DEV_USERNAME="devadmin"
   $env:TV_DEV_PASSWORD="YourStrongDevPassword123!"
   $env:TV_DEV_EMAIL="devadmin@example.com"
   # Optional: defaults to ROLE_USER; set to ROLE_ADMIN to create an administrator
   $env:TV_DEV_ROLE="ROLE_ADMIN"
   ```
   *Security Note: `DevUserInitializer` is strictly gated by `@Profile("dev")` and `TV_DEV_SEED_ENABLED=true`. It is disabled by default and never runs in production. Existing user and email collisions are preserved without modifying existing passwords or roles.*

### Step 4: Production Administrator Provisioning (Render / Neon Cloud)
In production, automatic seeders are permanently disabled to prevent unauthorized account creation. Because TrustVault does not expose a public registration endpoint, administrator accounts must be provisioned or promoted via an authenticated database administration procedure:

#### A. Generating a BCrypt-12 Password Hash Offline
To avoid exposing plaintext passwords over the network or in shell history, use the built-in `PasswordHashGenerator` utility:
```powershell
# Interactive mode (prompts securely without echoing password to terminal):
.\mvnw.cmd -q exec:java

# Alternatively, explicitly specify the main class:
.\mvnw.cmd -q exec:java "-Dexec.mainClass=com.trustvault.security.PasswordHashGenerator"
```
The utility enforces minimum password complexity (>= 8 characters), uses BCrypt work factor 12 (4,096 iterations), and outputs the formatted hash:
```
BCrypt (strength 12) Hash:
$2a$12$KFmHRWSNokQaDEiB6Sa5qOs9mOsnrXBVpS.tKdkpf3pzhgvZEBm2G
```

#### B. First Administrator Creation in Neon
Connect to your Neon PostgreSQL instance via the **Neon Web Console SQL Editor** (authenticated over TLS with MFA) or `psql` with `sslmode=require`:
```sql
INSERT INTO app_users (username, password, email, role, enabled, created_at)
VALUES (
    'admin',
    '$2a$12$KFmHRWSNokQaDEiB6Sa5qOs9mOsnrXBVpS.tKdkpf3pzhgvZEBm2G',
    'admin@trustvault.io',
    'ROLE_ADMIN',
    true,
    CURRENT_TIMESTAMP
);
```

#### C. Promoting an Existing Account in Neon
If the user account already exists in Neon:
```sql
UPDATE app_users
SET role = 'ROLE_ADMIN'
WHERE username = '<target_username>';
```

*Verification:*
```sql
SELECT id, username, email, role, enabled FROM app_users WHERE username = '<target_username>';
```

*Admin Zero-Trust Policy:* Accounts with `ROLE_ADMIN` can access system-wide audit records (`/audit`), but are strictly barred by `DocumentAuthorizationService` from viewing, editing, or downloading private documents without explicit ownership or a collaborator share.

### Step 5: Port Configuration & Overrides
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
- **Verified Full Test Suite Result:** **416 tests run, 410 passed, 0 failures, 0 errors, 6 skipped.**
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

# Convex Cloud Storage Provider & Validation Tests
.\mvnw.cmd test -Dtest=ConvexStorageServiceTest
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
