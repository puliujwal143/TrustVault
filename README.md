# TrustVault — Secure Enterprise Document-Sharing Application

TrustVault is an enterprise document-sharing platform designed for confidential business operations. It combines fine-grained access control, isolated private document storage, and comprehensive audit trails.

---

## Phase 1: Project Foundation

This phase establishes the foundational architecture, dependency configuration, Spring Security baseline, and verification suite.

### Technology Stack

- **Runtime**: Java 21 LTS
- **Framework**: Spring Boot 3.3.5
- **Web**: Spring Web (REST) & Thymeleaf (Server-Side Rendering)
- **Security**: Spring Security 6
- **Persistence**: Spring Data JPA & Hibernate
- **Database**: PostgreSQL (Production/Dev), H2 (In-memory testing)
- **Validation**: Bean Validation (Hibernate Validator)
- **Build Tool**: Apache Maven with Maven Wrapper (`mvnw` / `mvnw.cmd`)
- **Testing**: JUnit 5, MockMvc, Spring Security Test

---

## Prerequisites

1. **Java Development Kit (JDK)**: Java 21 or higher.
   Verify your version:
   ```bash
   java -version
   # Expected output: openjdk version "21.x.x" ...
   ```
2. **Git**: For version control.
3. **Maven**: **No global Maven installation is required**. The included Maven Wrapper handles all build operations.
4. **PostgreSQL** (Optional for Phase 1 verification; required for full local runtime).

---

## Getting Started

### 1. Build and Run Tests

Using the Maven Wrapper:

**Windows (PowerShell or Command Prompt):**
```powershell
.\mvnw.cmd clean test
```

**Linux / macOS:**
```bash
./mvnw clean test
```

### 2. Run the Application Locally

**Windows:**
```powershell
.\mvnw.cmd spring-boot:run
```

**Linux / macOS:**
```bash
./mvnw spring-boot:run
```

The application starts by default on port `8080`.

### 3. Verify Health Endpoint

The health probe is exposed at `/api/health`:

```bash
curl http://localhost:8080/api/health
```

Expected JSON response:
```json
{
  "status": "UP",
  "service": "TrustVault",
  "timestamp": "2026-10-18T14:30:00.000000Z"
}
```

---

## Configuration & Environment Variables

Database credentials and server settings are managed through environment variables. **No credentials are hardcoded.**

Refer to `.env.example` for all configurable variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `trustvault` |
| `DB_USERNAME` | Database username | `postgres` |
| `DB_PASSWORD` | Database password | *(empty)* |
| `SPRING_DATASOURCE_URL` | Override full JDBC URL | *(auto-constructed from DB_* variables)* |
| `PORT` | HTTP Server port | `8080` |
| `STORAGE_UPLOAD_DIR` | Private document storage directory | `./private-storage/uploads` |

For automated unit and integration tests (`mvnw test`), the application automatically activates an in-memory H2 database with PostgreSQL compatibility mode, ensuring builds execute hermetically without an active PostgreSQL instance.

---

## Project Structure

```text
TrustVault/
├── .mvn/wrapper/              # Maven Wrapper properties and scripts
├── src/
│   ├── main/
│   │   ├── java/com/trustvault/
│   │   │   ├── audit/         # Audit logging and compliance tracking
│   │   │   ├── config/        # General application bean configurations
│   │   │   ├── controller/    # HTTP controllers and REST endpoints
│   │   │   ├── dto/           # Data Transfer Objects & API contracts
│   │   │   ├── entity/        # JPA persistent entity models
│   │   │   ├── exception/     # Centralized exception handlers
│   │   │   ├── repository/    # Spring Data JPA data access interfaces
│   │   │   ├── security/      # Spring Security configuration and access rules
│   │   │   ├── service/       # Business logic and transaction boundary
│   │   │   └── TrustVaultApplication.java  # Main application entry point
│   │   └── resources/
│   │       ├── application.yml # Environment-driven application settings
│   │       └── templates/     # Thymeleaf templates (Phase 2+)
│   └── test/
│       ├── java/com/trustvault/
│       │   ├── controller/
│       │   │   └── HealthControllerTest.java
│       │   └── TrustVaultApplicationTests.java
│       └── resources/
│           └── application.properties # Isolated test configuration (H2)
├── .env.example               # Environment variables template
├── .gitignore                 # Excludes build output, secrets, and private files
├── ARCHITECTURE.md            # Architectural responsibilities and security notes
├── mvnw                       # Maven Wrapper shell script (Linux/macOS)
├── mvnw.cmd                   # Maven Wrapper batch script (Windows)
├── pom.xml                    # Maven Project Object Model
└── README.md                  # Project documentation
```

---

## Security Baseline

1. **Spring Security Active**: Security is NOT globally disabled. All application routes require authentication by default. Only `/api/health` is explicitly whitelisted.
2. **Private File Storage**: Uploaded files will reside in a private file system location (`./private-storage/uploads`), outside the web server root.
3. **No Hardcoded Credentials**: Database passwords and sensitive properties are injected strictly via environment variables.
4. **Isolated Error Responses**: The `GlobalExceptionHandler` sanitizes error details, preventing internal stack traces or database errors from leaking to API consumers.
