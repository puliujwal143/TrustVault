# TrustVault — AI-Assisted Implementation Log

## Date: 2026-10-18 (Session 1 — Phase 1 Database-Backed Authentication)

### Context & Task
Implementation of Phase 1 Database-Backed User Authentication for TrustVault using Spring Security, Spring Data JPA, and BCrypt password hashing.

### User Prompt
> Implement database-backed authentication plan:
> 1. Add User JPA entity mapped to `app_users`, Role enum (`ROLE_USER`, `ROLE_ADMIN`), and UserRepository.
> 2. Add PasswordEncoder bean using BCrypt with strength 12.
> 3. Add CustomUserDetailsService backed by UserRepository.
> 4. Add internal UserService that creates users with hashed passwords and rejects duplicate usernames/emails. Never store or log plaintext passwords.
> 5. Update SecurityConfig to use database-backed authentication, preserve form login, CSRF protection, and session-fixation protection.
> 6. Do not introduce public registration, default production accounts, hardcoded credentials, or document upload endpoints.
> 7. Do not grant administrators automatic access to all document contents. Document-level authorization is a later phase.
> 8. Keep the health endpoint public and require authentication for all other application endpoints.
> 9. Respect the existing `ddl-auto: validate` configuration. Explain how local dev and test schemas are initialized.
> 10. Add integration tests for valid login, invalid credentials, disabled users, password hashing, and CSRF enforcement.
> 11. Create or update PROMPTS.md with actual prompt, response, issues found, and actual fix.
> 12. Run `.\mvnw.cmd test` and report results.

### Issues Identified & Technical Solutions

1. **Auto-Configured In-Memory User & Generated Password**:
   - *Issue*: Spring Security fell back to `UserDetailsServiceAutoConfiguration`, generating an ephemeral UUID password in logs because no custom user service or password encoder existed.
   - *Fix*: Implemented `CustomUserDetailsService` and registered a `BCryptPasswordEncoder` bean, allowing Spring Security's `DaoAuthenticationProvider` to authenticate against database records.

2. **PostgreSQL Reserved Keyword Collision**:
   - *Issue*: In PostgreSQL, `USER` is a reserved SQL keyword. An entity named `User` mapped to a default table name `user` causes SQL syntax errors during DDL execution.
   - *Fix*: Mapped the entity explicitly via `@Table(name = "app_users")` and documented the table structure in `schema.sql`.

3. **Circular Dependency Prevention**:
   - *Issue*: Registering `PasswordEncoder` inside `SecurityConfig` while injecting `CustomUserDetailsService` (which often interacts with password verification) can trigger Spring circular bean dependency issues.
   - *Fix*: Isolated `PasswordEncoder` into a standalone configuration class `PasswordConfig.java`.

4. **Spring Security 6 Session Fixation Configuration**:
   - *Issue*: `SessionFixationConfigurer` class reference was deprecated/inaccessible as a direct type in Spring Security 6.
   - *Fix*: Configured session fixation using lambda syntax: `session.sessionFixation(fixation -> fixation.changeSessionId())`.

5. **Spring Security 6 Content Negotiation on Logout**:
   - *Issue*: In Spring Security 6, a POST to `/logout` returns HTTP `204 No Content` for API clients unless the `Accept: text/html` header is present indicating a browser redirect to `/login?logout` (`302 Found`).
   - *Fix*: Added `.accept(MediaType.TEXT_HTML)` to the browser logout test to properly assert the redirect response.

### Files Created & Modified
- `src/main/java/com/trustvault/config/PasswordConfig.java` (Created)
- `src/main/java/com/trustvault/entity/Role.java` (Created)
- `src/main/java/com/trustvault/entity/User.java` (Created)
- `src/main/java/com/trustvault/repository/UserRepository.java` (Created)
- `src/main/java/com/trustvault/security/CustomUserDetailsService.java` (Created)
- `src/main/java/com/trustvault/service/UserService.java` (Created)
- `src/main/java/com/trustvault/security/SecurityConfig.java` (Updated)
- `src/main/resources/schema.sql` (Created)
- `src/test/java/com/trustvault/security/AuthenticationIntegrationTest.java` (Created)
- `PROMPTS.md` (Created)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 11 total across 3 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `AuthenticationIntegrationTest`: 8 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (11.229 s).

---

## Date: 2026-10-18 (Session 2 — Authentication Hardening Pass)

### Context & Task
Pre-commit code review and security hardening pass covering JPA lifecycle safety in entity `equals`/`hashCode`, username/email validation and normalization, concurrency race conditions, and password change methods.

### User Prompt
> Review the existing TrustVault authentication implementation and make a small hardening pass before we commit it:
> 1. Make UserService username validation consistent with User's 3–50 character constraint. Trim usernames consistently, and normalize emails consistently for creation and lookup.
> 2. Keep database unique constraints as the final protection against concurrent duplicate account creation. Explain how constraint violations are handled; do not rely only on existsBy checks.
> 3. Review User.equals() and hashCode() for JPA lifecycle safety. Remove or revise them using a well-explained approach, and add tests if appropriate.
> 4. Ensure password changes and account creation always use PasswordEncoder. Do not introduce public registration or an endpoint that lets users choose ROLE_ADMIN.
> 5. Keep CSRF protection, database-backed authentication, and session-fixation protection enabled.
> 6. Add or update tests for username length validation, whitespace handling, duplicate account handling, and password hashing.
> 7. Update PROMPTS.md with this actual review, the issues found, and the real changes made. Do not invent past prompts or commit hashes.
> 8. Run .\mvnw.cmd test and report the actual output.
> Do not implement document permissions, file uploads, or audit logging in this pass. Do not commit or push.

### Issues Identified & Technical Solutions

1. **JPA Lifecycle Mutation in `equals()` and `hashCode()`**:
   - *Issue*: `User.java` previously calculated `Objects.hash(id, username)`. When a transient entity (`id == null`) was added to a `HashSet` and subsequently persisted to the database, its `id` became populated. This changed the object's `hashCode()` while inside the collection, corrupting hash bucket lookups and causing `set.contains(user)` to fail. Direct field access (`other.username`) also risked bypassing Hibernate lazy proxies.
   - *Fix*: Revised `equals()` and `hashCode()` in `User.java` to rely exclusively on the unique natural business key `username` via getter `other.getUsername()`. Added an integration test proving a `User` inserted into a `HashSet` before saving is still found after saving.

2. **Validation Consistency & Normalization Gaps**:
   - *Issue*: `User.java` declared `@Size(min = 3, max = 50)` on `username`, but `UserService.java` only checked `.isBlank()`, allowing 1- or 2-character usernames to pass service validation and fail at JPA validation. Email casing was not normalized during lookup queries.
   - *Fix*: Enforced `3 <= trimmedUsername.length() <= 50` inside `UserService.createUser()`, trimmed all incoming usernames, and normalized emails to lowercase (`Locale.ROOT`) across all creation, search (`findByEmail`), and existence check (`existsByEmail`) methods.

3. **Concurrency Race Conditions on Account Creation**:
   - *Issue*: Relying solely on `existsByUsername()` and `existsByEmail()` allows race conditions under high concurrency where two threads pass validation simultaneously before either transaction commits.
   - *Fix*: Employed `userRepository.saveAndFlush(user)` wrapped in a `try-catch` catching `DataIntegrityViolationException`. Database unique constraints on `app_users(username)` and `app_users(email)` act as the authoritative final defense and are translated into clean, descriptive `IllegalArgumentException` errors.

4. **Missing Secure Password Change Method**:
   - *Issue*: `UserService` had no facility for existing users to update their credentials through `PasswordEncoder`.
   - *Fix*: Added `UserService.changePassword(username, rawCurrentPassword, rawNewPassword)` which verifies current credentials with `passwordEncoder.matches()`, enforces the 8-character minimum, hashes the new password with BCrypt, and logs the event without recording plaintext passwords.

### Files Created & Modified
- `src/main/java/com/trustvault/entity/User.java` (Updated with JPA natural key equals/hashCode and updatable=false on username)
- `src/main/java/com/trustvault/service/UserService.java` (Updated with 3-50 char username checks, email normalization, changePassword method, and DataIntegrityViolationException handling)
- `src/test/java/com/trustvault/security/AuthenticationIntegrationTest.java` (Updated with 5 new tests for username length, whitespace trimming, email normalization, password changing, and JPA Set identity)
- `PROMPTS.md` (Updated)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 16 total across 3 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `AuthenticationIntegrationTest`: 13 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (13.723 s).

---

## Date: 2026-10-18 (Session 3 — Session Management & Security Hardening Review)

### Context & Task
Focused hardening review of TrustVault's session lifecycle, deliberate session revocation policy upon password changes, sanitized error handling preventing SQL leakage, Spring Boot 3 `NoResourceFoundException` handling, and ASCII comment normalization.

### User Prompt
> Perform a focused hardening review of TrustVault's existing UserService and session-management implementation:
> 1. Review how Spring Security sessions are currently created and tracked.
> 2. Define and implement a deliberate policy for sessions after password changes. Explain whether the current session remains valid and how other active sessions are invalidated, if session tracking supports it.
> 3. Do not claim that sessions are revoked unless the implementation and tests prove it.
> 4. Remove raw database exception messages from routine logs. Do not expose SQL or database details to clients. Distinguish expected uniqueness violations from unrelated integrity failures where practical.
> 5. Preserve BCrypt hashing, current-password verification, username validation, email normalization, and database unique constraints.
> 6. Correct the mojibake in comments without changing unrelated files.
> 7. Add tests for the new behavior and run .\mvnw.cmd test.
> 8. Update PROMPTS.md with this actual review and the real changes made. Do not invent history or commit hashes.
> 9. Do not commit or push. Explain the changes and remaining limitations.

### Issues Identified & Technical Solutions

1. **Absence of Session Tracking & Revocation Mechanism**:
   - *Issue*: Spring Security by default relies on standard servlet container sessions without a central registry. When a user changed their password, old sessions on other devices or browsers remained indefinitely active because there was no way to enumerate or expire them.
   - *Fix*: Configured a `SessionRegistry` (`SessionRegistryImpl`) and `HttpSessionEventPublisher` in `SecurityConfig.java`, enabled session concurrency control (`maximumSessions(-1)`), and configured `expiredUrl("/login?expired")`. In `UserService.java`, integrated `SessionRegistry` to revoke all active sessions for a username upon password change via `revokeAllUserSessions()`, while providing `revokeOtherUserSessions(username, currentSessionId)` for selective revocation.

2. **Raw Database Exception & SQL Leakage in Logs**:
   - *Issue*: Catching `DataIntegrityViolationException` in `UserService.createUser()` was logging `ex.getMessage()`, which exposes internal SQL statements, table names (`app_users`), constraint names, and column data in routine logs.
   - *Fix*: Implemented `isDuplicateConstraintViolation()` helper that distinguishes uniqueness collisions from unrelated integrity failures. Sanitized warning logs to record only that a uniqueness collision occurred for the username without printing raw SQL. Unrelated integrity failures log clean errors and throw sanitized `IllegalStateException`.

3. **Spring Boot 3 Catch-All Exception Handling Conflict**:
   - *Issue*: In Spring Boot 3 / Spring Framework 6.1, unmapped endpoints throw `NoResourceFoundException`. `GlobalExceptionHandler` previously caught generic `Exception.class` and returned HTTP 500, masking legitimate 404 Not Found responses on unmapped routes.
   - *Fix*: Added dedicated `@ExceptionHandler(NoResourceFoundException.class)` in `GlobalExceptionHandler.java` mapping to HTTP 404 with structured `ErrorResponseDto`.

4. **Mojibake in Source Comments**:
   - *Issue*: Unicode en-dash characters (`\u2013`) in `UserService.java` lines 49 and 65 (`3–50 characters`) caused encoding artifacts and column misalignments in non-UTF-8 console environments.
   - *Fix*: Replaced Unicode en-dashes with standard ASCII hyphens (`-`).

### Files Created & Modified
- `src/main/java/com/trustvault/security/SecurityConfig.java` (Added SessionRegistry bean, HttpSessionEventPublisher, and expiredUrl configuration)
- `src/main/java/com/trustvault/service/UserService.java` (Injected SessionRegistry, added revokeAllUserSessions/revokeOtherUserSessions, sanitized DataIntegrityViolationException logging, and removed mojibake)
- `src/main/java/com/trustvault/exception/GlobalExceptionHandler.java` (Added NoResourceFoundException handler for 404 mapping)
- `src/test/java/com/trustvault/security/AuthenticationIntegrationTest.java` (Added tests for session revocation after password change, selective session revocation, and sanitized exception verification)
- `PROMPTS.md` (Updated with Session 3 audit entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 19 total across 3 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `AuthenticationIntegrationTest`: 16 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (15.418 s).

---

## Date: 2026-10-18 (Session 4 — Transaction-Safe Session Revocation & SecurityConfig Refinement)

### Context & Task
Implementation of two targeted security improvements identified during the read-only security review: transaction-safe session revocation in `UserService`, explicit bean injection of `SessionRegistry` in `SecurityConfig`, and documenting horizontal scalability limits for in-memory session tracking in `ARCHITECTURE.md`.

### User Prompt
> Implement the two targeted improvements identified in the TrustVault read-only security review.
>
> 1. **Transaction-safe session revocation**
>    - Inspect `UserService.changePassword()` and its transaction boundary.
>    - Ensure active sessions are revoked only after the password update transaction successfully commits.
>    - Use Spring transaction synchronization appropriately. Handle the case where no transaction synchronization is active without silently skipping necessary security behavior.
>    - Add tests proving that a successful password change revokes sessions and that a rolled-back transaction does not revoke sessions prematurely.
>    - Avoid duplicate session-revocation callbacks.
>
> 2. **Explicit SessionRegistry injection**
>    - Update `SecurityConfig.securityFilterChain()` to receive `SessionRegistry` as a method parameter and use that instance in the session-management configuration.
>    - Preserve the existing session-fixation protection, unlimited concurrent-session policy, session registry, and expired-session redirect.
>    - Run the complete test suite with `.\mvnw.cmd test`.
>
> 3. **Documentation**
>    - Inspect the existing architecture documentation before editing.
>    - If `ARCHITECTURE.md` exists, document that `SessionRegistryImpl` is in-memory and that cross-instance session revocation is not guaranteed in a horizontally scaled deployment.
>    - Do not create unrelated documentation or claim distributed-session support.
>
> 4. **Honesty and scope**
>    - Update `PROMPTS.md` with the actual prompt, changes, test results, and limitations.
>    - Do not fabricate test results, commit hashes, or previous history.
>    - Do not commit or push.
>    - Do not implement document permissions, file uploads, or audit storage in this pass.
>
> At the end, list every changed file, explain the important code changes in beginner-friendly language, report the exact test totals, and identify any tests or behaviors that remain unverified.

### Issues Identified & Technical Solutions

1. **Premature Session Revocation Prior to Transaction Commit**:
   - *Issue*: `UserService.changePassword()` called `revokeAllUserSessions()` immediately after `userRepository.save(user)`. If the transaction failed during commit or an outer transaction rolled back, the user's password remained unchanged in the database, but all active sessions were already marked as expired in `SessionRegistry`.
   - *Fix*: Created `scheduleSessionRevocationAfterCommit()` and static inner class `UserSessionRevocationSynchronization`. When `TransactionSynchronizationManager.isSynchronizationActive()` is true, session revocation is registered via `afterCommit()`, firing only after the database transaction commits successfully. If transaction synchronization is inactive, revocation executes immediately so security revocation is never silently skipped. To prevent duplicate callbacks, `UserSessionRevocationSynchronization` implements `equals`/`hashCode` based on normalized username, and registration checks `TransactionSynchronizationManager.getSynchronizations().contains(sync)`. Furthermore, only `afterCommit()` is overridden (avoiding duplicate invocations from `afterCompletion()`).

2. **Explicit `SessionRegistry` Injection in `SecurityConfig`**:
   - *Issue*: In `SecurityConfig.java`, `securityFilterChain` previously obtained the registry by invoking the `@Bean` method directly (`sessionRegistry()`), relying on CGLIB configuration proxying.
   - *Fix*: Refactored `securityFilterChain(HttpSecurity http, SessionRegistry sessionRegistry)` to take `SessionRegistry` as an explicit method parameter and passed that instance to `.sessionManagement().sessionRegistry(sessionRegistry)`. Session fixation protection (`changeSessionId()`), unlimited concurrency (`maximumSessions(-1)`), and expired URL redirect (`/login?expired`) were preserved.

3. **In-Memory Session Storage & Horizontal Scalability Documentation**:
   - *Issue*: `ARCHITECTURE.md` lacked explicit documentation noting that `SessionRegistryImpl` operates strictly in JVM memory, which does not guarantee cross-node revocation in clustered environments.
   - *Fix*: Added Section 7 to `ARCHITECTURE.md` explaining session tracking mechanics and explicitly documenting that `SessionRegistryImpl` is an in-memory implementation suited for single-node deployments; cross-node session revocation in a horizontally scaled architecture requires a distributed session store.

### Files Created & Modified
- `src/main/java/com/trustvault/security/SecurityConfig.java` (Explicit `SessionRegistry` injection into `securityFilterChain`)
- `src/main/java/com/trustvault/service/UserService.java` (Added post-commit transaction synchronization for session revocation, fallback for inactive synchronization, and duplicate callback prevention)
- `src/test/java/com/trustvault/security/AuthenticationIntegrationTest.java` (Added tests for rolled-back transaction session preservation, inactive synchronization fallback, and duplicate synchronization prevention)
- `ARCHITECTURE.md` (Added Section 7 documenting in-memory session registry and horizontal scalability limitations)
- `PROMPTS.md` (Updated with Session 4 entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 22 total across 3 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `AuthenticationIntegrationTest`: 19 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (21.840 s).

### Limitations & Deferred Scope
- Document permissions, secure file storage/uploads, and database-backed audit logging remain deferred to Phase 2+.
- `SessionRegistryImpl` remains an in-memory single-node solution; distributed session synchronization across multi-instance clusters is not supported in Phase 1.

---

## Date: 2026-10-21 (Session 5 — Phase 2 Milestone 2.1 Data Model & Schema Foundation)

### Context & Task
Implementation of Milestone 2.1 for Phase 2: Data Model and Database Schema Foundation for secure document ownership and sharing. Scoped strictly to entities, repositories, schema DDL, and persistence tests without implementing authorization services, controllers, file storage, or audit logging.

### User Prompt
> I approve the overall Phase 2 design, with the following refinements.
>
> Security decisions:
> 1. A storage UUID is an identifier, never a substitute for authorization.
> 2. Return 404 for documents the caller has no permission to discover. Return 403 when an existing grantee attempts an operation not allowed by their grant. Keep this behavior consistent across endpoints and tests.
> 3. Resolve the authenticated caller from Spring Security and user records from the database. Never trust client-supplied owner IDs or user IDs to establish identity.
> 4. Preserve the existing username normalization and uniqueness behavior. Do not introduce case-insensitive usernames unless the current schema and authentication code are deliberately migrated to support them.
> 5. ROLE_ADMIN must not bypass document authorization.
> 6. Re-check current grants on each document operation. Do not cache permissions in the HTTP session.
> 7. Keep file uploads, file streaming, and audit-event persistence out of this milestone.
>
> Implement **Milestone 2.1 — Data Model & Schema Foundation only**.
>
> Tasks:
> - Inspect the existing source, schema.sql, test configuration, and Git status before editing.
> - Add `SharePermission` with READ and EDIT.
> - Add the `Document` entity with a required owner, UUID storage key, validated title, optional bounded description, and creation/update timestamps.
> - Add the `DocumentShare` entity linking a document to a grantee with a permission and grant timestamp.
> - Add the corresponding repositories.
> - Add the tables, foreign keys, uniqueness constraints, and indexes to schema.sql, preserving the existing app_users schema.
> - Ensure JPA mappings match the SQL schema and the existing PostgreSQL/H2 test setup.
> - Prevent duplicate grants using a database unique constraint on document_id and grantee_id. Plan for an existing grant to be updated when the owner changes READ to EDIT or EDIT to READ.
> - Prevent owners from creating a share grant to themselves at the service/API layer later; do not pretend the data-model milestone already enforces this.
> - Review entity equals/hashCode behavior carefully; do not introduce unstable equality for persisted entities.
> - Add focused repository/persistence tests for document ownership mapping, share persistence, foreign-key/unique constraints where practical, and entity lifecycle behavior.
> - Do not implement authorization services or controllers yet.
> - Do not run destructive database operations, commit, or push.
> - Update PROMPTS.md with the actual prompt, implementation, issues, fixes, and real test results.
> - Run `.\mvnw.cmd test` and report the exact output summary.
>
> Before editing, report any blocking compatibility issue you find. After implementation, list changed files, explain the code in beginner-friendly language, and identify what remains unverified. Do not claim security features are implemented until they actually are.

### Issues Identified & Technical Solutions

1. **Foreign Key Integrity in Multi-Class Test Execution**:
   - *Issue*: `DocumentPersistenceTest` created document records with foreign keys referencing `app_users`. When `AuthenticationIntegrationTest` executed subsequently in the same test run, its `setUp()` called `userRepository.deleteAll()`, failing with a referential integrity constraint violation on `fk_documents_owner` (`FKD1DQC3GVAO4T4H7JKDH5WKBYJ`).
   - *Fix*: Added `@AfterEach` in `DocumentPersistenceTest` to delete `document_shares`, `documents`, and `app_users` after every test. Additionally updated `AuthenticationIntegrationTest.setUp()` to defensively clean up document tables before users.

2. **Hibernate Schema Generation Missing Cascade Action**:
   - *Issue*: In `DocumentShare`, mapping `document` and `grantee` with `@ManyToOne` without Hibernate cascade action caused H2 DDL generated via `create-drop` to omit `ON DELETE CASCADE`. When `documentRepository.delete(doc)` was invoked in cascade deletion tests, the database rejected the delete with a foreign key violation (`FK2Q6I3YMOBF720H0XQ3GDVHABN`).
   - *Fix*: Added `@org.hibernate.annotations.OnDelete(action = OnDeleteAction.CASCADE)` to `document` and `grantee` in `DocumentShare.java`, aligning Hibernate's generated DDL with the explicit `ON DELETE CASCADE` definitions in `schema.sql`.

3. **JPA Entity Identity & Set Invariance**:
   - *Issue*: Basing entity equality on auto-generated primary keys causes mutable hash codes when transitioning from transient (`id == null`) to persistent (`id != null`), corrupting hash buckets in collections like `HashSet`.
   - *Fix*: Implemented `equals()` and `hashCode()` for `Document` based on its immutable `UUID storageKey`, and for `DocumentShare` based on its natural composite key `(document, grantee)`. Added tests verifying `set.contains()` remains true across `saveAndFlush()` transitions.

### Files Created & Modified
- `src/main/java/com/trustvault/entity/SharePermission.java` (Created: enum with READ and EDIT and permission hierarchy helpers)
- `src/main/java/com/trustvault/entity/Document.java` (Created: JPA entity with owner FK, UUID storageKey, validated title, bounded description, and timestamps)
- `src/main/java/com/trustvault/entity/DocumentShare.java` (Created: JPA entity linking document and grantee with permission and unique constraint)
- `src/main/java/com/trustvault/repository/DocumentRepository.java` (Created: repository with derived and JPQL accessible documents queries)
- `src/main/java/com/trustvault/repository/DocumentShareRepository.java` (Created: repository for share lookup, existence checks, and deletion)
- `src/main/resources/schema.sql` (Updated: added DDL for `documents` and `document_shares` tables, foreign keys, unique constraints, and indexes)
- `src/test/java/com/trustvault/repository/DocumentPersistenceTest.java` (Created: 9 persistence tests covering ownership, shares, constraints, updates, Set stability, cascade deletion, and accessible queries)
- `src/test/java/com/trustvault/security/AuthenticationIntegrationTest.java` (Updated: defensive cleanup of document tables in setUp)
- `PROMPTS.md` (Updated: Session 5 audit entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 31 total across 4 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `AuthenticationIntegrationTest`: 19 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (20.002 s).

### Limitations & Deferred Scope
- Authorization services (`DocumentAuthorizationService`, `DocumentService`, `DocumentShareService`) and REST controllers (`/api/documents`) are not yet implemented (scheduled for Milestones 2.2 and 2.3).
- Service-level rule preventing owners from sharing documents with themselves is deferred to Milestone 2.2.
- File uploads, disk blob storage, streaming endpoints, and audit-event logging remain deferred to Phase 3.

---

## Date: 2026-10-21 (Session 6 — Phase 2 Milestone 2.2 Secure Authorization Engine)

### Context & Task
Implementation of Milestone 2.2: Document Authorization Service, Document Service, and Document Share Service. Centralized authorization predicate engine, owner vs grantee permission hierarchy, anti-IDOR 404/403 denial distinction, admin isolation, DTO representations, and comprehensive authorization integration tests.

### User Prompt
> # TrustVault — Milestone 2.2: Secure Authorization Engine
>
> Implement the next milestone of TrustVault: document authorization and service-layer enforcement.
>
> ## 1. Existing Project Context
> The project is located at D:\TrustVault.
> Current stack: Java 21, Spring Boot 3.3.5, Spring Security 6, Spring Data JPA / Hibernate, PostgreSQL, Maven Wrapper, JUnit 5.
> Existing local Git milestones: 9be212e, 6c7fcbc.
>
> ## 2. Scope and Restrictions
> Implement only the service and authorization layer for this milestone.
> Do NOT create REST controllers, implement file uploads/downloads, implement audit persistence, or commit/push.
>
> ## 3. Implement DocumentAuthorizationService
> Create DocumentAuthorizationService with methods: isOwner, canRead, canEdit, getAuthorizedDocument.
> Rules: Owner has full control. READ grantee reads metadata only. EDIT grantee reads and edits metadata. Unshared users cannot access. ROLE_ADMIN must not bypass authorization. Check DB permissions on every operation.
>
> ## 4. Denial and Error Handling
> Return 404 for unshared/unknown documents to stop ID enumeration. Return 403 when an existing grantee attempts an unauthorized operation.
>
> ## 5. Implement DocumentService
> Service methods for create, retrieve, update, delete, and list accessible documents. Resolve owner from authenticated principal. Validate titles and descriptions.
>
> ## 6. Implement DocumentShareService
> Service methods for grant, update, revoke, and list shares. Only owner can manage shares. Reject self-grant, nonexistent users, and disabled accounts. Prevent duplicate shares.
>
> ## 7. Authorization Test Requirements
> Test all 15 required authorization scenarios.
>
> ## 8. PROMPTS.md Documentation & 9. Final Verification
> Append entry to PROMPTS.md, run .\mvnw.cmd test, report results without committing or pushing.

### Issues Identified & Technical Solutions

1. **`LazyInitializationException` on Proxy Traversal Outside Active Session**:
   - *Issue*: In `DocumentAuthorizationTest.owner_canGrantAndRevokeAccess`, calling `shares.get(0).getGrantee().getUsername()` after service method completion triggered `org.hibernate.LazyInitializationException: could not initialize proxy [com.trustvault.entity.User] - no Session` because `grantee` was marked `FetchType.LAZY` and `open-in-view` is set to `false`.
   - *Fix*: Added `@EntityGraph(attributePaths = {"grantee", "document"})` to `DocumentShareRepository.findByDocumentId` and `findByDocumentIdAndGranteeUsername`, and `@EntityGraph(attributePaths = {"owner"})` to `DocumentRepository.findById` and `findByStorageKey`. This ensures Spring Data JPA eagerly fetches the associated entities during repository queries in the active transaction, eliminating lazy loading failures and preventing N+1 select queries.

2. **Consistent Anti-IDOR / BOLA Denial Handling (404 vs 403)**:
   - *Issue*: Returning HTTP 403 for unshared documents reveals to an attacker that a document with that ID exists (resource discovery vulnerability).
   - *Fix*: Standardized on `ResourceNotFoundException` (mapped to HTTP 404 in `GlobalExceptionHandler`) for both non-existent documents and documents where the caller has neither ownership nor an active grant. Reserved `AccessDeniedException` (HTTP 403) strictly for authenticated grantees attempting operations beyond their granted permissions (e.g. `READ` grantee attempting `updateDocument`, or any grantee attempting document deletion or share management).

3. **Admin Privilege Isolation (`ROLE_ADMIN`)**:
   - *Issue*: Administrative accounts could inadvertently bypass document-level ownership checks if role checks override object-level checks.
   - *Fix*: Configured `DocumentAuthorizationService` to evaluate ownership and explicit share records strictly against the database without granting `ROLE_ADMIN` any automatic bypass. An administrator attempting to access an unshared document receives `ResourceNotFoundException` (404).

### Files Created & Modified
- `src/main/java/com/trustvault/exception/ResourceNotFoundException.java` (Created: custom exception for 404 mapping)
- `src/main/java/com/trustvault/exception/GlobalExceptionHandler.java` (Updated: added 404 handler for `ResourceNotFoundException` and 400 handler for `IllegalArgumentException`)
- `src/main/java/com/trustvault/dto/DocumentResponseDto.java` (Created: API response boundary DTO)
- `src/main/java/com/trustvault/dto/DocumentShareResponseDto.java` (Created: share response boundary DTO)
- `src/main/java/com/trustvault/service/DocumentAuthorizationService.java` (Created: central authorization predicate engine)
- `src/main/java/com/trustvault/service/DocumentService.java` (Created: document metadata management with authorization checks)
- `src/main/java/com/trustvault/service/DocumentShareService.java` (Created: share management with owner enforcement and self-grant rejection)
- `src/main/java/com/trustvault/repository/DocumentRepository.java` (Updated: added `@EntityGraph` for eager owner retrieval)
- `src/main/java/com/trustvault/repository/DocumentShareRepository.java` (Updated: added `@EntityGraph` for eager grantee and document retrieval)
- `src/test/java/com/trustvault/service/DocumentAuthorizationTest.java` (Created: 15 integration tests covering all required security scenarios)
- `PROMPTS.md` (Updated: Session 6 audit entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 46 total across 5 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 15 tests passed.
  - `AuthenticationIntegrationTest`: 19 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (57.628 s).

### Limitations & Deferred Scope
- REST controllers (`DocumentController`, `DocumentShareController`) are not yet implemented (scheduled for Milestone 2.3).
- File storage on disk, upload streaming, and audit-event logging remain deferred to Phase 3.
- No files have been committed or pushed to Git.

---

## Date: 2026-10-21 (Session 7 — Milestone 2.2 Security Review Hardening Pass)

### Context & Task
Implementation of targeted security hardening and race condition fixes identified during the Milestone 2.2 read-only security review: concurrent share grant serialization, disabled-owner document unavailability and listing exclusion policy, session revocation upon account deactivation in `UserService`, coordination between document updates and share revocations via pessimistic locking, and comprehensive negative boundary tests.

### User Prompt
> # TrustVault Milestone 2.2 — Security Review Fixes
>
> Perform a focused hardening pass based on the read-only security review. Inspect the actual source before editing. Do not create REST controllers, implement file uploads, add audit storage, commit, or push.
>
> 1. **Fix concurrent share grants**
>    - Address the race where two concurrent requests both find no existing share and attempt to insert one.
>    - Preserve the unique database constraint `uq_document_grantee`.
>    - Handle uniqueness conflicts safely without exposing raw database exceptions or returning an unexplained HTTP 500.
>    - Do not assume that catching an exception and querying again in the same failed transaction will work. Account for Spring transaction rollback behavior.
>    - Choose a robust approach compatible with PostgreSQL and H2 test configuration.
>    - Preserve in-place permission updates for existing grants.
>    - Add tests for duplicate grants and concurrent behavior.
>
> 2. **Define and enforce disabled-owner behavior**
>    - Adopt this policy: when a document owner is disabled, their documents are unavailable to grantees and are omitted from accessible-document listings. The documents and share records remain stored. If the owner is re-enabled, access can resume according to the current grants.
>    - Update `DocumentAuthorizationService` to enforce this policy consistently.
>    - Update `DocumentRepository.findAllAccessibleByUsername()` so disabled owners' documents are excluded from a grantee's listing.
>    - Preserve the existing rule that disabled requesting users cannot access documents.
>    - Avoid revealing document existence to unauthorized callers.
>    - Add tests for direct access and listing when an owner is disabled.
>
> 3. **Handle session revocation when accounts are disabled**
>    - Determine whether an account-deactivation service method already exists in `UserService`.
>    - Implement transactional deactivation method expiring active sessions after transaction commit.
>    - Use existing session-revocation mechanisms and avoid duplicating logic.
>    - Add tests proving deactivation expires registered sessions and disabled users cannot access documents.
>
> 4. **Clarify revocation versus in-flight edits**
>    - Determine whether an update authorized just before revocation can commit after revocation.
>    - Implement locking behavior coordinating both operations on the same document state.
>    - Add concurrency test and document precise limitations.
>
> 5. **Add missing negative tests**
>    - Revoking nonexistent share.
>    - Creating document for disabled owner.
>    - Blank or null document title.
>    - Title exceeding 255 characters.
>    - Description exceeding 1000 characters.
>    - Disabled-owner documents inaccessible and absent from listings.
>    - Concurrency and session revocation tests.
>
> 6. **Preserve existing security baseline & 7. Documentation and verification**
>    - Run `.\mvnw.cmd test` and report results.
>    - List every changed file and explain in beginner-friendly language.
>    - State explicitly which concurrency guarantees remain unverified.
>    - Do not commit or push.

### Issues Identified & Technical Solutions

1. **Concurrent Share Grant Race Condition (`uq_document_grantee`)**:
   - *Issue*: Two parallel `grantAccess` requests for the same `(documentId, grantee)` simultaneously checked `findByDocumentIdAndGranteeUsername()`. Both observed an empty result and attempted `INSERT`. The second transaction collided with the database unique constraint `uq_document_grantee` and failed with `DataIntegrityViolationException`. Catching this exception within the same Spring transaction to retry the query is invalid because Hibernate marks the session/transaction as rollback-only.
   - *Fix*: Added `findByIdForUpdate` with `LockModeType.PESSIMISTIC_WRITE` on `DocumentRepository`. In `DocumentShareService.grantAccess()`, the document row is locked exclusively before checking or saving shares. The second concurrent grant request blocks until the first transaction commits, then reads the newly committed share and updates it in place. The database unique constraint is preserved as defense-in-depth.

2. **Disabled-Owner Document Availability & Listing Policy**:
   - *Issue*: When a document owner's account was disabled, grantees could still read and edit their shared documents, and the documents continued to appear in grantee accessible listings.
   - *Fix*:
     - Updated `DocumentAuthorizationService.getAuthorizedDocument()`, `canRead()`, and `canEdit()` to check `document.getOwner().isEnabled()`. If the owner is disabled, access is rejected with `ResourceNotFoundException("Document not found: " + documentId)` (HTTP 404), preserving anti-IDOR masking.
     - Updated `DocumentRepository.findAllAccessibleByUsername()` JPQL query to include `AND d.owner.enabled = true`. Documents of disabled owners are omitted from grantee listings without altering or deleting stored records.
     - When the owner is reactivated, `d.owner.enabled = true` immediately restores accessibility according to active grants.

3. **Session Revocation on Account Deactivation**:
   - *Issue*: `UserService` had no account deactivation method, and deactivating a user directly left active sessions valid in Spring Security's `SessionRegistry`.
   - *Fix*: Added `UserService.deactivateUser(String username)` and `UserService.reactivateUser(String username)`. `deactivateUser` sets `enabled = false` and registers post-commit transaction synchronization via `scheduleSessionRevocationAfterCommit()`. When the transaction commits, all active sessions for that user in `SessionRegistry` are marked expired, causing subsequent requests to be redirected to `/login?expired` by `ConcurrentSessionFilter`.

4. **Coordination Between In-Flight Edits and Share Revocation**:
   - *Issue*: An edit request authorized immediately before a concurrent share revocation could commit its changes after the revocation committed because `Document` and `DocumentShare` were separate rows without coordination.
   - *Fix*: Configured both `DocumentService.updateDocument()` and `DocumentShareService.revokeAccess()` (as well as `deleteDocument()`) to coordinate on the parent `Document` entity by acquiring a pessimistic write lock via `documentRepository.findByIdForUpdate(documentId)`. Authorization in `updateDocument` is evaluated strictly under the lock. If revocation commits first, `updateDocument` unblocks, checks authorization under the lock, finds the share deleted, and throws 404. If update commits first, the update completed before revocation.

### Files Created & Modified
- `src/main/java/com/trustvault/repository/DocumentRepository.java` (Added `findByIdForUpdate` with `PESSIMISTIC_WRITE`; updated `findAllAccessibleByUsername` with `d.owner.enabled = true`)
- `src/main/java/com/trustvault/service/DocumentAuthorizationService.java` (Enforced disabled-owner policy returning 404 in `getAuthorizedDocument`, `getAuthorizedDocumentForOwner`, `canRead`, and `canEdit`)
- `src/main/java/com/trustvault/service/DocumentService.java` (Added `findByIdForUpdate` pessimistic locking to `updateDocument` and `deleteDocument`)
- `src/main/java/com/trustvault/service/DocumentShareService.java` (Injected `DocumentRepository`; added `findByIdForUpdate` locking to `grantAccess` and `revokeAccess`)
- `src/main/java/com/trustvault/service/UserService.java` (Added `deactivateUser` with post-commit session revocation and `reactivateUser`)
- `src/test/java/com/trustvault/service/DocumentAuthorizationTest.java` (Added 8 negative and concurrency tests: nonexistent share revocation, disabled owner creation, blank/excessive title, excessive description, update validation, disabled-owner policy lifecycle, and multi-threaded concurrent grant serialization)
- `src/test/java/com/trustvault/security/AuthenticationIntegrationTest.java` (Added 2 tests: `deactivateUser` session revocation and rollback safety)
- `PROMPTS.md` (Updated: Session 7 audit entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 56 total across 5 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 23 tests passed.
  - `AuthenticationIntegrationTest`: 21 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (21.506 s).

### Unverified Concurrency Guarantees & Limitations
- **Distributed Session Invalidation**: `SessionRegistryImpl` remains an in-memory single-node solution; deactivation invalidates sessions on the local node only. Multi-instance cluster synchronization requires a distributed session store.
- **Pessimistic Lock Wait Timeout**: `findByIdForUpdate` uses default database lock wait timeouts. Under severe lock contention or long transactions, database lock timeout exceptions could occur instead of application-level errors.
- **No Files Committed or Pushed**: All changes remain local in the working tree.

---

## Date: 2026-10-21 (Session 8 — Transaction & Authorization Lock Ordering Hardening)

### Context & Task
Review and hardening of transaction boundaries and authorization ordering in Milestone 2.2: acquiring pessimistic row locks on documents prior to evaluating owner and EDIT authorizations, using the locked entity consistently to eliminate stale data and duplicate queries, and adding tests proving clean serialization between in-flight edits and share revocations.

### User Prompt
> Review and fix the transaction and authorization ordering in TrustVault Milestone 2.2.
>
> Important: Do not commit or push. Do not create controllers, upload functionality, or audit persistence.
>
> 1. In `DocumentShareService.grantAccess()` and `revokeAccess()`, acquire the document row lock using `findByIdForUpdate(documentId)` before performing the final owner authorization check. Use the locked document consistently, and ensure authorization is rechecked while the lock is held.
>
> 2. In `DocumentService.deleteDocument()`, acquire the document lock before the final owner authorization check. Delete the locked/authorized document, not a potentially stale entity loaded before locking.
>
> 3. Review `DocumentService.updateDocument()` and confirm that it acquires the lock and checks EDIT permission within the same transaction. Preserve the existing READ/EDIT/owner-only rules, disabled-owner policy, 404 behavior for inaccessible documents, and admin non-bypass rule.
>
> 4. Review the repository lock query and transaction boundaries. Ensure the database lock remains held until the relevant transaction commits. Avoid unnecessary duplicate queries where safely possible.
>
> 5. Add or update tests to cover authorization and lock ordering where practical. Do not claim a concurrency guarantee unless a test demonstrates it.
>
> 6. Update `PROMPTS.md` with the actual changes and test results. Run `.\mvnw.cmd test` and report the exact outcome.
>
> Return the files changed, explain the ordering fixes in beginner-friendly language, report the actual test totals, and list any remaining limitations. Do not commit or push.

### Issues Identified & Technical Solutions

1. **Lock-Before-Authorization Ordering in `DocumentShareService`**:
   - *Issue*: `grantAccess()` and `revokeAccess()` previously performed owner authorization without a lock, then issued a separate `findByIdForUpdate()` whose returned entity was discarded. This evaluated ownership before acquiring the row lock and produced two queries per operation.
   - *Fix*: Added `getAuthorizedDocumentForOwnerForUpdate()` in `DocumentAuthorizationService`. It executes `documentRepository.findByIdForUpdate(documentId)` to obtain the row lock first, and immediately verifies caller ownership and enabled status on the locked entity under that lock. `grantAccess()` uses the locked entity directly when instantiating `DocumentShare`, eliminating the duplicate query and ensuring the lock is held throughout the transaction.

2. **Lock-Before-Authorization in `DocumentService.deleteDocument()`**:
   - *Issue*: `deleteDocument()` loaded the document without a lock, acquired a lock in a subsequent statement, and deleted the entity instance loaded prior to locking.
   - *Fix*: `deleteDocument()` now calls `authorizationService.getAuthorizedDocumentForOwnerForUpdate()`, acquiring the pessimistic write lock before owner authorization, and passes the locked, verified `Document` entity to `documentRepository.delete()`.

3. **Single-Query Lock & EDIT Authorization in `DocumentService.updateDocument()`**:
   - *Issue*: `updateDocument()` previously called `documentRepository.findByIdForUpdate()` and then called `authorizationService.getAuthorizedDocument()`, executing two separate database queries for the same document in the same transaction.
   - *Fix*: Added `authorizationService.getAuthorizedDocumentForUpdate()`, which locks the document via `findByIdForUpdate()` and evaluates EDIT permissions directly on the locked entity. It eliminates the duplicate query while strictly preserving all existing authorization rules (owner access, EDIT grantee access, 403 on READ grantee, 404 on unshared user or disabled owner/user, and no `ROLE_ADMIN` bypass).

4. **Integration Tests for Lock Ordering & Concurrency**:
   - Added test 24 in `DocumentAuthorizationTest.java`: verifies `getAuthorizedDocumentForUpdate()` and `getAuthorizedDocumentForOwnerForUpdate()` enforce all owner, EDIT, READ-denial (403), and unshared-denial (404) rules under pessimistic lock.
   - Added test 25 in `DocumentAuthorizationTest.java`: tests concurrent `updateDocument()` and `revokeAccess()` running across parallel threads, verifying that operations serialize cleanly without unhandled errors or stale updates committing after revocation.

### Files Created & Modified
- `src/main/java/com/trustvault/service/DocumentAuthorizationService.java` (Added `getAuthorizedDocumentForUpdate`, `getAuthorizedDocumentForOwnerForUpdate`, and shared `authorizeDocument`/`authorizeDocumentForOwner` methods)
- `src/main/java/com/trustvault/service/DocumentService.java` (Updated `updateDocument()` and `deleteDocument()` to use locking-aware authorization methods, eliminating duplicate queries)
- `src/main/java/com/trustvault/service/DocumentShareService.java` (Updated `grantAccess()` and `revokeAccess()` to use `getAuthorizedDocumentForOwnerForUpdate()`, removed redundant `DocumentRepository` dependency)
- `src/test/java/com/trustvault/service/DocumentAuthorizationTest.java` (Added tests 24 and 25 covering locked authorization methods and concurrent update vs revocation)
- `PROMPTS.md` (Updated: Session 8 audit entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 58 total across 5 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 25 tests passed.
  - `AuthenticationIntegrationTest`: 21 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (21.470 s).

### Unverified Concurrency Guarantees & Limitations
- **Distributed Session Invalidation**: `SessionRegistryImpl` remains an in-memory single-node solution; deactivation invalidates sessions on the local node only. Multi-instance cluster synchronization requires a distributed session store.
- **Pessimistic Lock Wait Timeout**: `findByIdForUpdate` uses default database lock wait timeouts. Under severe lock contention or long transactions, database lock timeout exceptions could occur instead of application-level errors.
- **No Files Committed or Pushed**: All changes remain local in the working tree.

---

## Date: 2026-10-21 (Session 9 — Milestone 2.3 Stage 1: Audit Schema and Core Data Model)

### Context & Task
Implementation of TrustVault Milestone 2.3 — Stage 1: Audit Schema and Core Data Model. Defined the `audit_events` relational table and indexes in `schema.sql`, created `AuditAction` and `AuditOutcome` enums, implemented the immutable `AuditEvent` JPA entity with Hibernate `@Immutable`, created the append-only `AuditEventRepository` extending Spring Data's `Repository` marker interface, and validated behavior with persistence integration tests.

### User Prompt
> Proceed with TrustVault Milestone 2.3 — Stage 1: Audit Schema and Core Data Model ONLY.
>
> Use the approved refined design. Inspect the existing code and schema.sql before editing.
>
> Implement:
> 1. Add the audit_events table and indexes to schema.sql. Do not add a foreign key from audit_events.document_id to documents, so document deletion never requires modifying or deleting historical audit rows.
> 2. Create AuditAction.java with the planned action enum values.
> 3. Create AuditOutcome.java with SUCCESS, DENIED, and FAILURE.
> 4. Create AuditEvent.java as a JPA entity mapped to audit_events. Use Hibernate @Immutable, immutable fields, no public setters, UUID event ID, and an Instant timestamp.
> 5. Create AuditEventRepository.java extending Spring Data's Repository marker interface, exposing only save and necessary read methods. Do not expose delete or update operations.
> 6. Keep document_id and document_storage_key as independent audit snapshots. Preserve audit rows when documents are deleted.
> 7. Do not log sensitive data or add arbitrary details fields beyond the approved schema.
> 8. Follow the project's existing Java and JPA conventions. Ensure schema initialization remains compatible with PostgreSQL and the existing H2 test setup.
>
> Scope restrictions:
> - Do not integrate auditing into DocumentService, DocumentShareService, UserService, or DocumentAuthorizationService yet.
> - Do not implement AuditService or denial logging yet.
> - Do not create controllers or APIs.
> - Do not stage, commit, or push.
> - Do not claim database-level tamper resistance from @Immutable alone.
>
> Add focused tests for entity persistence, repository read/save behavior, and schema compatibility where practical. Run .\mvnw.cmd test and report the exact results. Update PROMPTS.md with the actual work and test results. List every changed file and any unresolved issues.

### Issues Identified & Technical Solutions

1. **Audit Preservation Across Document Deletions**:
   - *Issue*: A traditional foreign key constraint with `ON DELETE CASCADE` destroys audit records when a document is deleted. `ON DELETE RESTRICT` forbids document deletion once audited. `ON DELETE SET NULL` requires issuing `UPDATE` statements against `audit_events`, violating the append-only, tamper-resistant requirement and erasing document ID history.
   - *Fix*: Configured `audit_events.document_id` as an unconstrained logical reference (`BIGINT`) paired with the immutable `document_storage_key` (`UUID`). When a document is deleted, no SQL `UPDATE` or `DELETE` is issued against `audit_events`. Existing audit rows permanently preserve both the numeric document ID and the storage UUID.

2. **Tamper-Resistant Application Layer via Minimal Repository API**:
   - *Issue*: Extending `JpaRepository` or `CrudRepository` automatically exposes mutating operations (`delete`, `deleteById`, `deleteAll`, `saveAllAndFlush`), allowing application services to alter or purge audit logs.
   - *Fix*: Extended Spring Data's root `Repository<AuditEvent, Long>` marker interface. Only `save()` and read-only query methods were declared. Reflection tests verify that zero delete, remove, or update methods exist on the repository interface.

3. **Hibernate Entity Immutability**:
   - *Issue*: Ordinary JPA entities allow in-memory field mutation that gets committed to the database during flush/commit dirty checking.
   - *Fix*: Annotated `AuditEvent` with `@org.hibernate.annotations.Immutable`, marked all columns `updatable = false`, and omitted public setters. Verified via integration test that modifying loaded entity fields in a managed session does not generate SQL `UPDATE` queries.

4. **Bean Validation vs. Data Integrity Exceptions**:
   - *Issue*: Attempting to persist entities with null required fields triggered Bean Validation's `jakarta.validation.ConstraintViolationException` during Hibernate's `preInsert` listener rather than Spring's translated `DataIntegrityViolationException`.
   - *Fix*: Updated test assertion to catch `ConstraintViolationException`, properly asserting validation failure on required audit fields.

### Files Created & Modified
- `src/main/resources/schema.sql` (Updated: added `audit_events` table and 6 performance indexes)
- `src/main/java/com/trustvault/audit/AuditAction.java` (Created: 11 action enum values)
- `src/main/java/com/trustvault/audit/AuditOutcome.java` (Created: SUCCESS, DENIED, FAILURE)
- `src/main/java/com/trustvault/audit/AuditEvent.java` (Created: immutable JPA entity mapped to `audit_events`)
- `src/main/java/com/trustvault/repository/AuditEventRepository.java` (Created: append-only Spring Data repository)
- `src/test/java/com/trustvault/repository/AuditEventPersistenceTest.java` (Created: 9 integration tests covering persistence, queries, deletion survival, immutability, and reflection)
- `PROMPTS.md` (Updated: Session 9 audit entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 67 total across 6 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 25 tests passed.
  - `AuditEventPersistenceTest`: 9 tests passed.
  - `AuthenticationIntegrationTest`: 21 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (21.670 s).

### Unresolved Issues & Technical Limitations
- **Database-Level Privilege Separation**: Hibernate `@Immutable` and repository method omission protect against application-level modifications during standard ORM workflows. They do not prevent raw native SQL updates (`createNativeQuery`) or direct database modification by users with superuser credentials. Production PostgreSQL environments require database role hardening (`REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM trustvault_app`).
- **Service-Layer Integration Pending**: Auditing is not yet wired into `DocumentService`, `DocumentShareService`, `DocumentAuthorizationService`, or `UserService` (scoped for Stage 2 & 3).
- **No Files Committed or Pushed**: All changes remain local in the working tree.

---

## Date: 2026-10-21 (Session 10 — Milestone 2.3 Stage 2: AuditService Engine)

### Context & Task
Implementation of TrustVault Milestone 2.3 — Stage 2: AuditService Engine. Implemented `AuditService` orchestrating transactional audit recording, same-transaction business event rollback consistency, isolated autonomous security-denial logging with connection-pool safeguards, privacy sanitization, and administrative read query operations.

### User Prompt
> We have completed TrustVault Milestone 2.3 — Stage 1: Audit Schema and Core Data Model.
>
> Now inspect the current project and implement Milestone 2.3 — Stage 2: AuditService Engine ONLY.
>
> Requirements:
> 1. Inspect AuditEvent, AuditEventRepository, the transaction configuration, datasource connection-pool settings, and existing service transaction boundaries before making changes.
> 2. Implement AuditService methods to record audit events using the existing AuditAction and AuditOutcome enums.
> 3. Successful business audit events must participate in the same transaction as the business operation, so a rollback also rolls back its SUCCESS audit event.
> 4. Design security-denial logging carefully. REQUIRES_NEW does not release the connection held by an outer transaction, so explain and account for possible connection-pool exhaustion before choosing the implementation.
> 5. Never log passwords, session IDs, CSRF tokens, document titles, descriptions, file contents, or arbitrary user-controlled strings.
> 6. Preserve the append-only repository design. Do not add repository update or delete methods.
> 7. Do not integrate auditing into DocumentService, DocumentShareService, UserService, or DocumentAuthorizationService yet.
> 8. Do not create controllers or API endpoints.
> 9. Add focused tests for audit persistence, transaction rollback, denial-event transaction behavior, and relevant failure cases.
> 10. Update PROMPTS.md with the actual work and exact test results.
> 11. Run .\mvnw.cmd test and report the exact test count, failures, errors, skipped tests, and BUILD result.
> 12. Do not stage, commit, or push any changes.
>
> When finished, report the implementation decisions, every changed file, test results, and unresolved issues. If a critical transaction-design issue prevents safe implementation, explain it before proceeding rather than hiding it.

### Issues Identified & Technical Solutions

1. **Atomicity & Phantom Success Prevention via `Propagation.REQUIRED`**:
   - *Requirement*: Audit events recording successful business operations must commit or roll back with the business transaction.
   - *Solution*: `AuditService.recordEvent()` and `recordSuccess()` use `@Transactional(propagation = Propagation.REQUIRED)`. When invoked within an active business transaction, the audit record is written within the same database transaction. If the business mutation fails or rolls back, the database rolls back the `SUCCESS` audit record atomically. Tested via `recordSuccess_shouldRollbackWhenBusinessTransactionRollsBack`.

2. **Security Denial Survival & Connection Pool Deadlock Mitigation (`Propagation.REQUIRES_NEW`)**:
   - *Issue*: Recording security denials requires the audit event to commit and survive even when the caller's transaction is subsequently aborted by an authorization exception (403/404). However, `Propagation.REQUIRES_NEW` suspends the outer transaction while keeping its physical JDBC connection pinned to the calling thread. If HikariCP pool size is smaller than the concurrent thread demand ($PoolSize < 2N$), thread pool exhaustion and deadlock can occur.
   - *Solution*:
     a) `AuditService.recordSecurityDenial()` executes a single, atomic `save()` in an isolated transaction that commits immediately, holding the second connection for only a few milliseconds.
     b) Added fail-safe error handling: if connection acquisition or database insert fails during denial logging, an error is logged to SLF4J and the method returns `Optional.empty()` without rethrowing, ensuring that pool issues never mask, bypass, or alter the security denial decision.
     c) Documented production pool sizing requirement ($PoolSize \ge 2 \times MaxWorkerThreads$) for deployments utilizing nested autonomous transactions.
     d) Tested via `recordSecurityDenial_inNewTransaction_shouldSurviveOuterTransactionRollback`.

3. **Privacy & Input Sanitization Guardrails**:
   - *Requirement*: Never log passwords, session IDs, CSRF tokens, document titles, descriptions, or raw user-controlled strings.
   - *Solution*: `AuditService` accepts discrete resource IDs (`documentId`, `documentStorageKey`) and enum types (`AuditAction`, `AuditOutcome`). All string metadata (`actorUsername`, `targetUsername`, `clientIp`, `details`) is strictly length-bounded (`MAX_USERNAME_LENGTH = 50`, `MAX_IP_LENGTH = 45`, `MAX_DETAILS_LENGTH = 500`) and sanitized by normalizing newlines, carriage returns, and tabs to spaces to prevent log forging.

### Files Created & Modified
- `src/main/java/com/trustvault/service/AuditService.java` (Created: AuditService engine with `recordEvent`, `recordSuccess`, `recordSecurityDenial`, and read queries)
- `src/test/java/com/trustvault/service/AuditServiceTest.java` (Created: 8 integration tests covering same-transaction commit, rollback isolation, denial survival in REQUIRES_NEW, standalone denial, validation, sanitization, and query pagination)
- `PROMPTS.md` (Updated: Session 10 audit entry)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 75 total across 7 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 25 tests passed.
  - `AuditEventPersistenceTest`: 9 tests passed.
  - `AuditServiceTest`: 8 tests passed.
  - `AuthenticationIntegrationTest`: 21 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (28.230 s).

### Unresolved Issues & Technical Limitations
- **Connection Pool Sizing in High-Concurrency Environments**: When `recordSecurityDenial` runs in `REQUIRES_NEW` within an active transaction, the thread holds two connections. In small pool configurations (e.g. 10 connections), no more than 5 concurrent threads can execute nested denial logging simultaneously without queueing for connections. In production, HikariCP maximum pool size should be sized to at least $2 \times TomcatWorkerThreads$.
- **Service Integration Pending (Stage 3)**: Auditing is not yet wired into `DocumentService`, `DocumentShareService`, `DocumentAuthorizationService`, or `UserService` (scoped for Stage 3).
- **No Files Committed or Pushed**: All changes remain local in the working tree.

---

## Date: 2026-10-21 (Session 11 — Milestone 2.3 Stage 3: Business-Service Audit Integration)

### Context & Task
Implementation of TrustVault Milestone 2.3 — Stage 3: Business-Service Audit Integration. Wired audit events across all business services (`DocumentService`, `DocumentShareService`, `UserService`, and `DocumentAuthorizationService`), ensuring same-transaction rollback consistency for successful mutations, safe autonomous `REQUIRES_NEW` denial logging at the authorization boundary, collection query isolation, strict privacy guardrails, and comprehensive integration testing.

### User Prompt
> Implement TrustVault Milestone 2.3 — Stage 3: Business-Service Audit Integration.
>
> First inspect the existing services, AuditService, AuditAction, AuditOutcome, transaction boundaries, and tests. Follow the current architecture and avoid unrelated refactoring.
>
> Scope:
> 1. Integrate successful audit events into DocumentService:
>    - DOCUMENT_CREATE
>    - DOCUMENT_READ
>    - DOCUMENT_UPDATE
>    - DOCUMENT_DELETE
> 2. Integrate successful audit events into DocumentShareService:
>    - SHARE_GRANT when a new share is created
>    - SHARE_UPDATE when an existing permission is changed
>    - SHARE_REVOKE when a share is removed
> 3. Integrate account lifecycle and credential events into UserService:
>    - USER_DEACTIVATE
>    - USER_REACTIVATE
>    - PASSWORD_CHANGE
> 4. Integrate ACCESS_DENIED recording at the appropriate authorization boundary in DocumentAuthorizationService. Preserve the existing 404 anti-enumeration behavior for unshared documents and the existing 403 behavior for forbidden actions by known grantees. Do not change authorization decisions merely to produce audit events.
> 5. Successful mutation audit events must use the same transaction as their business operations. A rolled-back operation must not leave a committed SUCCESS event.
> 6. Invoke recordSecurityDenial through the injected AuditService Spring proxy. Catch failures at the authorization boundary so denial-audit failures do not replace the original authorization exception. Do not assume REQUIRES_NEW releases the outer transaction's connection; document the remaining connection-pool limitation.
> 7. Do not record a successful READ until authorization has succeeded. Avoid logging one event per item when listing collections. Do not expose audit history through a controller or API in this stage.
> 8. Never log passwords, session identifiers, CSRF tokens, document titles, descriptions, file contents, or arbitrary user-controlled text. Use only approved event metadata.
> 9. Add tests covering successful event creation, rollback atomicity, share grant/update/revoke distinctions, user lifecycle events, authorized reads, and denial logging for forbidden and nonexistent-resource cases. Preserve existing tests and security behavior.
> 10. Update PROMPTS.md with the actual implementation, issues, and exact test results.
>
> Run .\mvnw.cmd test and report exact counts for tests, failures, errors, skipped tests, and build status.
>
> Do not stage, commit, or push anything. Do not create controllers or upload functionality. List every changed file and unresolved limitations.

### Issues Identified & Technical Solutions

1. **Multiple Constructors & Spring `@Autowired` Ambiguity**:
   - *Issue*: Adding overloaded constructors accepting `AuditService` alongside existing 3-arg constructors caused Spring's dependency injection container to fail at boot with `BeanCreationException: No default constructor found`.
   - *Solution*: Explicitly annotated the 4-arg constructor in `DocumentAuthorizationService`, `DocumentService`, `DocumentShareService`, and `UserService` with `@Autowired`. The 3-arg constructors were preserved for backwards compatibility with direct unit test instantiations.

2. **Mutation Transaction Atomicity & Rollback Consistency (`Propagation.REQUIRED`)**:
   - *Requirement*: A rolled-back operation must never leave a committed `SUCCESS` audit event.
   - *Solution*: Business mutation operations (`DOCUMENT_CREATE`, `DOCUMENT_UPDATE`, `DOCUMENT_DELETE`, `SHARE_GRANT`, `SHARE_UPDATE`, `SHARE_REVOKE`, `USER_DEACTIVATE`, `USER_REACTIVATE`, `PASSWORD_CHANGE`) invoke `auditService.recordSuccess()`. Because `recordSuccess()` participates in the caller's transaction (`Propagation.REQUIRED`), any business transaction rollback automatically rolls back the associated audit row. Verified via `rollbackAtomicity_shouldRollbackAuditEventWhenMutationFails` and `rollbackAtomicity_shouldRollbackUpdateEventWhenUpdateFails`.

3. **Authorized READ Auditing Timing & Collection Query Isolation**:
   - *Requirement*: Do not log successful read events until authorization has succeeded; do not emit individual events when listing collections.
   - *Solution*: In `DocumentService.getDocument()`, `authorizationService.getAuthorizedDocument()` is evaluated first; only if authorization succeeds is `DOCUMENT_READ` emitted. If authorization fails (throwing 404 or 403), read logging is skipped and denial logging takes over. Collection listing methods (`listAccessibleDocuments`, `listShares`) deliberately do not emit per-item audit events, preventing log flooding and query overhead.

4. **Security Denial Auditing & Boundary Defense at Authorization Layer**:
   - *Requirement*: Record `ACCESS_DENIED` while preserving 404 anti-enumeration for unshared documents and 403 for forbidden actions by known grantees. Denial logging failures must not replace or alter the authorization exception.
   - *Solution*: In `DocumentAuthorizationService`, `auditSecurityDenial()` delegates to `auditService.recordSecurityDenial()` via the injected Spring proxy (`REQUIRES_NEW`), persisting denial events even when the caller rolls back. The call is wrapped in a defensive `try-catch` block at the boundary to ensure that any transient persistence or pool failure during denial logging is logged to SLF4J but never replaces or alters the primary `ResourceNotFoundException` (404) or `AccessDeniedException` (403).

5. **Privacy Guardrails & Data Sanitization**:
   - *Requirement*: Never log passwords, session identifiers, CSRF tokens, document titles, descriptions, file contents, or arbitrary user-controlled text.
   - *Solution*: Document titles and descriptions are completely omitted from audit event payloads. Passwords (both current and new) are never passed to audit methods. Only discrete entity IDs, immutable UUID storage keys, usernames, standardized reason strings, and enum permission names (`READ`, `EDIT`) are logged, with inputs strictly length-bounded and control-character sanitized.

### Files Created & Modified
- `src/main/java/com/trustvault/service/DocumentService.java` (Updated: Added `@Autowired` constructor and audit integration for `DOCUMENT_CREATE`, `DOCUMENT_READ`, `DOCUMENT_UPDATE`, `DOCUMENT_DELETE`)
- `src/main/java/com/trustvault/service/DocumentShareService.java` (Updated: Added `@Autowired` constructor and audit integration for `SHARE_GRANT`, `SHARE_UPDATE`, `SHARE_REVOKE`, plus self-grant and disabled grantee denials)
- `src/main/java/com/trustvault/service/UserService.java` (Updated: Added `@Autowired` constructor and audit integration for `USER_DEACTIVATE`, `USER_REACTIVATE`, `PASSWORD_CHANGE`)
- `src/main/java/com/trustvault/service/DocumentAuthorizationService.java` (Updated: Added `@Autowired` constructor and fail-safe `auditSecurityDenial` boundary integration)
- `src/test/java/com/trustvault/service/BusinessAuditIntegrationTest.java` (Created: 14 end-to-end integration tests for business audit logging, rollback atomicity, share distinctions, user lifecycle, read validation, collection isolation, and security denials)
- `PROMPTS.md` (Updated: Session 11 implementation log)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 89 total across 8 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 25 tests passed.
  - `AuditEventPersistenceTest`: 9 tests passed.
  - `AuditServiceTest`: 8 tests passed.
  - `BusinessAuditIntegrationTest`: 14 tests passed.
  - `AuthenticationIntegrationTest`: 21 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (34.323 s).

### Unresolved Issues & Technical Limitations
- **HikariCP Connection Pool Pinning in `REQUIRES_NEW`**: During denial logging within an active transaction, the outer transaction retains its pinned connection while the inner `recordSecurityDenial()` acquires a second connection. In high-concurrency environments or under denial-of-service attempts, this can exhaust small connection pools. While our defensive try-catch at the authorization boundary prevents denial logging failures from breaking security decisions, an asynchronous outbox or decoupled event bus should be considered if traffic scales significantly.
- **Audit History API Not Yet Implemented**: Audit records are stored append-only in the database and accessible via `AuditService` query methods, but no REST API or administrative UI is exposed in this milestone (by design).
- **No Files Committed or Pushed**: All changes remain local in the working tree.

---

## Date: 2026-10-21 (Session 12 — Milestone 2.4 Stage 1: Storage Engine Abstraction & Local Disk Implementation)

### Context & Task
Implementation of TrustVault Milestone 2.4 — Stage 1: Storage Engine Abstraction and Local Disk Implementation ONLY. Implemented `StorageService` interface, `LocalStorageService`, `StorageException`, `StorageFileNotFoundException`, path traversal defenses, atomic temporary-file staging promotion, and 14 dedicated storage tests while keeping the storage layer completely decoupled from `DocumentService`, database entities, and HTTP controllers.

### User Prompt
> Implement TrustVault Milestone 2.4 — Stage 1: Storage Engine Abstraction and Local Disk Implementation ONLY.
>
> Project context:
> - Java 21, Spring Boot, Spring Security, Spring Data JPA, PostgreSQL.
> - Existing document authorization, sharing, and append-only audit system.
> - Latest local Git checkpoint is clean.
> - Existing full test suite passed 89 tests.
> - GitHub repository must remain private. Do not push.
> - Free tools and dependencies only.
>
> Design decisions:
> - The document owner and collaborators with EDIT permission will be allowed to upload/replace files in a later stage.
> - READ collaborators will only be allowed to download.
> - Allowed file formats will be PDF, DOCX, XLSX, PPTX, TXT, CSV, PNG, and JPEG.
> - Maximum file size will default to 10 MB.
> - These upload policies are for later stages; do not implement upload endpoints now.
>
> Stage 1 scope:
> 1. Inspect the existing project configuration, .gitignore, tests, and architecture documentation.
> 2. Create a StorageService interface with methods suitable for storing, loading, checking existence, and deleting files using UUID storage keys.
> 3. Create LocalStorageService that stores files in a configurable private directory, defaulting to ./private-storage/uploads.
> 4. Ensure storage is outside public/static resource directories. Never use a client-supplied filename to construct a disk path.
> 5. Normalize and validate resolved paths to prevent path traversal. Use UUID-based storage names.
> 6. Implement safe file creation, loading, and deletion with clear error handling. Use atomic file moves where applicable and supported.
> 7. Create suitable storage exceptions.
> 8. Add focused tests for store, load, delete, missing files, invalid keys/paths, and relevant filesystem failures.
> 9. Keep the storage implementation independent of DocumentService for now.
> 10. Do not modify the Document entity or schema in this stage.
> 11. Do not add controllers, upload/download endpoints, file validation, audit actions, or service integration yet.
> 12. Do not stage, commit, or push anything.
> 13. Update PROMPTS.md with the actual work and exact test results. Report every changed file and unresolved issues.
>
> Run .\mvnw.cmd test and report the exact number of tests, failures, errors, skipped tests, and build status.
>
> Important: Do not claim that local filesystem storage is durable on free hosting platforms with ephemeral disks. Document that limitation for later deployment planning.

### Issues Identified & Technical Solutions

1. **Gitignore Pattern Masking Java Package**:
   - *Issue*: A bare `storage/` directory pattern in `.gitignore` matched any folder named `storage` in the tree, which unintentionally ignored Java source code packages `src/main/java/com/trustvault/storage` and `src/test/java/com/trustvault/storage`.
   - *Solution*: Anchored filesystem storage directory exclusions to the repository root with leading slashes (`/private-storage/`, `/uploads/`, `/storage/`, `/data/`), ensuring on-disk storage directories remain untracked while Java source files are correctly tracked.

2. **Path Traversal Defense & Identifier Obfuscation**:
   - *Requirement*: Files must be referenced by UUID, never by client-supplied filenames, and resolved paths must never escape the storage root.
   - *Solution*: `LocalStorageService.resolvePath(UUID storageKey)` validates that the storage key conforms to standard UUID formatting and resolves destination paths as `{storageKey}.bin`. It normalizes the path and enforces `resolved.getParent().equals(rootLocation)` and `resolved.startsWith(rootLocation)`, rejecting any traversal attempt with `StorageException`.

3. **Atomic File Creation & Partial Write Protection**:
   - *Requirement*: Protect against corrupt or partially-written files on filesystem or network stream interruptions.
   - *Solution*: Content is streamed into a unique temporary staging file (`tv_upload_{storageKey}_{uuid}.tmp`) first. Once streaming completes successfully, `Files.move(..., ATOMIC_MOVE, REPLACE_EXISTING)` atomically promotes the temporary file to `{storageKey}.bin` (falling back to standard replacement if atomic move is unsupported on the underlying filesystem). A `finally` block guarantees that temporary files are deleted if an error occurs during write.

4. **Proactive Web Static Asset Directory Defense**:
   - *Requirement*: Storage directories must never reside inside public or static web folders.
   - *Solution*: `LocalStorageService.init()` inspects the normalized root path and throws `StorageException` if it contains `/static`, `/public`, `/resources/static`, or equivalent web-accessible target folders.

### Files Created & Modified
- `.gitignore` (Modified: Anchored private storage directory patterns to root)
- `src/main/java/com/trustvault/storage/StorageService.java` (Created: Core storage abstraction interface)
- `src/main/java/com/trustvault/storage/LocalStorageService.java` (Created: Local disk implementation with atomic staging and path traversal checks)
- `src/main/java/com/trustvault/storage/StorageException.java` (Created: Base storage runtime exception)
- `src/main/java/com/trustvault/storage/StorageFileNotFoundException.java` (Created: Specialized exception for missing files)
- `src/main/java/com/trustvault/storage/package-info.java` (Created: Storage package documentation)
- `src/test/java/com/trustvault/storage/LocalStorageServiceTest.java` (Created: 14 unit and integration tests)
- `PROMPTS.md` (Updated: Session 12 implementation log)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 103 total across 9 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 25 tests passed.
  - `AuditEventPersistenceTest`: 9 tests passed.
  - `AuditServiceTest`: 8 tests passed.
  - `BusinessAuditIntegrationTest`: 14 tests passed.
  - `AuthenticationIntegrationTest`: 21 tests passed.
  - `LocalStorageServiceTest`: 14 tests passed.
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 0.
- Build Status: `BUILD SUCCESS` (34.245 s).

### Unresolved Issues & Technical Limitations
- **Ephemeral Filesystem Limitation on Free Cloud Hosting**: `LocalStorageService` writes files to the local host or container filesystem. On free cloud platforms (e.g. Render, Railway, Fly.io free tiers), containers have ephemeral disk storage that is wiped on restarts, sleep cycles, and redeployments. For persistent cloud deployments, a persistent volume mount or an S3-compatible cloud object storage provider (e.g. Cloudflare R2 or Backblaze B2, both offering 10 GB free storage) will be required. The `StorageService` interface was specifically designed to enable this pluggability in future milestones.
- **Service Integration & Metadata Pending (Stage 2 & 3)**: `StorageService` is currently standalone and not yet wired into `Document`, `DocumentService`, `DocumentAuthorizationService`, or HTTP endpoints (deferred to subsequent stages by design).
- **No Files Committed or Pushed**: All changes remain local in the working tree.

---

## Date: 2026-10-21 (Session 13 — Milestone 2.4 Stage 1 Security Hardening Pass)

### Context & Task
Security hardening of TrustVault Milestone 2.4 Stage 1 following the completed read-only security review. Implemented symbolic link defenses across all storage read, check, delete, and store operations; startup cleanup restricted strictly to application-owned `tv_upload_*.tmp` staging files; filesystem root path rejection (`/`, `C:\`); and narrowly scoped Git exclusion rules without impacting Java source packages.

### User Prompt
> Harden TrustVault Milestone 2.4 Stage 1 based on the completed read-only security review.
>
> Inspect the existing LocalStorageService.java, StorageService.java, LocalStorageServiceTest.java, and .gitignore before editing.
>
> Implement these fixes only:
>
> 1. Symbolic links:
>    - Reject symbolic links for existing storage files before reading or reporting their presence.
>    - Ensure loadAsStream(), loadAsResource(), exists(), getFileSize(), and delete() cannot follow a planted symlink outside the storage root.
>    - Account for filesystem race conditions as far as practical with Java NIO. Do not claim perfect protection against every local filesystem race.
>    - Add tests that create a symlink inside a temporary storage directory pointing to an external test file. Where symlinks are unsupported or prohibited by the OS, skip that test explicitly rather than pretending it passed.
>
> 2. Startup cleanup:
>    - During init(), clean up only abandoned staging files matching the exact application-owned naming pattern tv_upload_*.tmp.
>    - Do not delete final .bin files or unrelated .tmp files.
>    - Add tests for cleanup behavior.
>
> 3. Storage root safety:
>    - Reject filesystem roots such as / and C:\ during initialization.
>    - Preserve valid temporary test directories and the default ./private-storage/uploads path.
>    - Add tests for rejected root configurations.
>
> 4. Git exclusions:
>    - Add narrowly scoped rules for generated .bin and .tmp files without excluding Java source files or unrelated repository content.
>    - Check the effective ignore behavior for src/main/java/com/trustvault/storage/ and src/test/java/com/trustvault/storage/.
>
> 5. Keep the current StorageService API and do not integrate DocumentService, database metadata, file validation, controllers, or upload endpoints yet.
>
> 6. Update PROMPTS.md with the actual changes, issues, and exact test results.
>
> Run .\mvnw.cmd test and report the exact totals, failures, errors, skipped tests, and build status.
>
> Do not stage, commit, or push anything. List every changed file and any remaining limitations. Do not claim that a security test ran successfully if the environment skipped it.

### Issues Identified & Technical Solutions

1. **Symbolic Link Traversal & Planted Symlink Defense**:
   - *Issue*: A pre-existing or maliciously planted symbolic link inside the storage directory could point to sensitive external files (e.g. `/etc/passwd` or application configuration). Methods like `loadAsStream()`, `loadAsResource()`, `getFileSize()`, `exists()`, and `delete()` could follow the link outside the storage root or report misleading existence/size.
   - *Solution*:
     - In `LocalStorageService.java`, added `assertNotSymbolicLink(Path filePath, UUID storageKey)` which checks `Files.isSymbolicLink(filePath)` and throws `StorageException("Security violation: Symbolic links are strictly prohibited: " + storageKey)`.
     - Applied `LinkOption.NOFOLLOW_LINKS` to `Files.exists()`, `Files.isRegularFile()`, and `Files.newInputStream(filePath, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)` to mitigate race conditions at the NIO/OS level.
     - Updated `exists()` to return `false` if `isSymbolicLink(filePath)` is detected.
     - Updated `delete()` to reject symlinks via `assertNotSymbolicLink` before executing `Files.deleteIfExists()`.
     - Updated `store()` to verify that the target path is not a symlink both before streaming and prior to atomic rename promotion.
     - In `LocalStorageServiceTest.java`, created 6 dedicated symlink test methods (`exists`, `loadAsResource`, `loadAsStream`, `getFileSize`, `delete`, `store`). If symlink creation fails due to host OS restrictions (`SeCreateSymbolicLinkPrivilege` not held on Windows), the tests use `org.junit.jupiter.api.Assumptions.assumeTrue(...)` to explicitly skip the test rather than falsely claiming a pass.

2. **Startup Cleanup Scope Restriction**:
   - *Issue*: An overly broad cleanup on startup could accidentally delete valid storage files (`.bin`) or unrelated temporary files generated by other tooling.
   - *Solution*: Implemented `cleanupAbandonedStagingFiles()` in `init()`, using a `DirectoryStream<Path>` filter matching only `tv_upload_*.tmp`. Verified via integration test `init_shouldCleanUpOnlyApplicationStagingFiles()` that abandoned staging files are deleted while final `.bin` files, unrelated `.tmp` files (`unrelated_backup.tmp`), and other files are strictly preserved.

3. **Storage Root Traversal & Root Directory Safety**:
   - *Issue*: Configuring root paths such as `/` (Linux root) or `C:\` (Windows drive root) as the storage root could lead to accidental modification, traversal, or deletion of operating system and application files during `deleteAll()`.
   - *Solution*: Implemented `assertStoragePathNotRoot()` during `init()`. Checks `normalized.getParent() == null || normalized.equals(normalized.getRoot())` and throws `StorageException` if a root directory is configured, while allowing valid relative paths (e.g. `./private-storage/uploads`) and temporary test directories. Added test `init_shouldRejectFilesystemRootPaths()` verifying rejection of `/` and all roots returned by `FileSystems.getDefault().getRootDirectories()`.

4. **Narrowly Scoped Git Exclusions**:
   - *Issue*: Ensuring generated storage artifacts (`.bin` and `.tmp`) are ignored by Git without accidentally ignoring Java source code in `src/main/java/com/trustvault/storage/` or `src/test/java/com/trustvault/storage/`.
   - *Solution*: Added `*.bin` and `*.tmp` under the `# Private uploaded documents & storage directories` section in `.gitignore`. Verified using `git check-ignore -v` that Java sources are tracked normally while disk binaries and staging temp files are ignored.

### Files Created & Modified
- `src/main/java/com/trustvault/storage/LocalStorageService.java` (Modified: Added symlink rejection, `LinkOption.NOFOLLOW_LINKS`, `assertStoragePathNotRoot`, and restricted startup cleanup)
- `src/test/java/com/trustvault/storage/LocalStorageServiceTest.java` (Modified: Added root path rejection, startup cleanup scope, and 6 symlink tests with explicit skip assumptions)
- `.gitignore` (Modified: Added `*.bin` and `*.tmp` rules)
- `PROMPTS.md` (Updated: Session 13 implementation log)

### Build & Verification Results
- Command: `.\mvnw.cmd test`
- Tests Executed: 112 total across 9 test classes:
  - `HealthControllerTest`: 2 tests passed.
  - `DocumentPersistenceTest`: 9 tests passed.
  - `DocumentAuthorizationTest`: 25 tests passed.
  - `AuditEventPersistenceTest`: 9 tests passed.
  - `AuditServiceTest`: 8 tests passed.
  - `BusinessAuditIntegrationTest`: 14 tests passed.
  - `AuthenticationIntegrationTest`: 21 tests passed.
  - `LocalStorageServiceTest`: 23 tests (17 passed, 6 skipped).
  - `TrustVaultApplicationTests`: 1 test passed.
- Failures: 0, Errors: 0, Skipped: 6.
- Build Status: `BUILD SUCCESS` (33.779 s).
- **Explicit Note on Skipped Tests**: Exactly 6 tests in `LocalStorageServiceTest` were skipped (`symlink_exists_shouldReturnFalseForPlantedSymlink`, `symlink_loadAsResource_shouldRejectPlantedSymlink`, `symlink_loadAsStream_shouldRejectPlantedSymlink`, `symlink_getFileSize_shouldRejectPlantedSymlink`, `symlink_delete_shouldRejectPlantedSymlink`, `symlink_store_shouldRejectPlantedSymlink`). On this Windows test host, Developer Mode is not active and unprivileged user accounts lack `SeCreateSymbolicLinkPrivilege`. Per design, `Assumptions.assumeTrue(...)` marked them as skipped rather than failing or falsely claiming pass.

### Unresolved Issues & Technical Limitations
- **Local Filesystem TOCTOU Concurrency Limitations**: Java NIO methods mitigate symlink attacks using `LinkOption.NOFOLLOW_LINKS` and pre-read assertions. However, true atomic non-following path resolution (e.g. `openat2` with `RESOLVE_NO_SYMLINKS` on modern Linux) is not fully exposed by Java NIO on all operating systems. Absolute protection against an attacker with concurrent local filesystem write access inside the storage directory cannot be guaranteed at the JVM layer alone without OS-level container isolation or dedicated mount permissions.
- **Symlink Test Execution Environment**: In CI/CD pipelines running on Linux containers or Windows environments with Developer Mode enabled, the 6 skipped symlink tests will execute fully and validate symlink rejection against live filesystem symlinks.
- **Storage Service Remains Standalone**: StorageService is not yet wired to `DocumentService`, DB entities, or HTTP controllers (by design; planned for subsequent stages).
- **Ephemeral Filesystem Limitation**: Local storage files on free cloud hosting instances reset upon container redeployments.
- **No Files Committed or Pushed**: All changes remain local in the working tree.