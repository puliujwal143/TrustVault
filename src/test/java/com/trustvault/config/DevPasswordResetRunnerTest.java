package com.trustvault.config;

import com.trustvault.audit.AuditAction;
import com.trustvault.audit.AuditEvent;
import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.Role;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.repository.AuditEventRepository;
import com.trustvault.repository.DocumentRepository;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit and integration tests for DevPasswordResetRunner:
 * - Disabled by default when 'dev' profile or property is missing.
 * - Production profile protection.
 * - Successful in-place password reset with BCrypt (strength 12).
 * - Preservation of user ID, email, role, enabled status, and createdAt.
 * - Preservation of documents, shares, and audit history.
 * - Rejection of targets other than 'devuser'.
 * - Gating on TV_DEV_SEED_ENABLED=true.
 * - Safe failure on missing/invalid passwords without secret exposure.
 * - Asynchronous application shutdown lifecycle execution.
 */
class DevPasswordResetRunnerTest {

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.reset-password.enabled=false",
            "spring.profiles.active=default"
    })
    @ActiveProfiles("default")
    @DisplayName("1. Disabled by Default Verification")
    class DisabledByDefaultTest {

        @Autowired
        private ApplicationContext applicationContext;

        @Test
        @DisplayName("DevPasswordResetRunner bean must NOT be present by default")
        void beanNotLoadedByDefault() {
            assertThat(applicationContext.containsBean("devPasswordResetRunner")).isFalse();
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.reset-password.enabled=false"
    })
    @ActiveProfiles("dev")
    @DisplayName("2. Profile-Only Verification (property still disabled)")
    class ProfileOnlyWithoutPropertyTest {

        @Autowired
        private ApplicationContext applicationContext;

        @Test
        @DisplayName("DevPasswordResetRunner bean must NOT be present when 'dev' profile is active but reset-password.enabled is false or missing")
        void beanNotLoadedWithoutProperty() {
            assertThat(applicationContext.containsBean("devPasswordResetRunner")).isFalse();
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.reset-password.enabled=true",
            "spring.profiles.active=default"
    })
    @ActiveProfiles("default")
    @DisplayName("3. Property-Only Without Dev Profile Verification")
    class PropertyOnlyWithoutDevProfileTest {

        @Autowired
        private ApplicationContext applicationContext;

        @Test
        @DisplayName("DevPasswordResetRunner bean must NOT be present when reset-password.enabled is true but 'dev' profile is absent")
        void beanNotLoadedWithoutDevProfile() {
            assertThat(applicationContext.containsBean("devPasswordResetRunner")).isFalse();
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.reset-password.enabled=false"
    })
    @DisplayName("4. Execution Logic & Security Invariants")
    class ExecutionLogicTest {

        @Autowired
        private UserService userService;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private DocumentRepository documentRepository;

        @Autowired
        private DocumentShareRepository documentShareRepository;

        @Autowired
        private AuditEventRepository auditEventRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private ApplicationContext applicationContext;

        @BeforeEach
        void setUp() {
            documentShareRepository.deleteAll();
            documentRepository.deleteAll();
            userRepository.deleteAll();
        }

        @Test
        @DisplayName("Successful reset: updates password to new BCrypt hash and preserves ID, email, role, enabled status")
        void successfulReset_updatesPasswordAndPreservesOtherFields() {
            // 1. Seed devuser with initial password
            String initialRawPassword = "OldPassword123!";
            User initialUser = userService.createUser("devuser", initialRawPassword, "devuser@trustvault.local", Role.ROLE_USER);

            Long expectedId = initialUser.getId();
            String expectedEmail = initialUser.getEmail();
            Role expectedRole = initialUser.getRole();
            boolean expectedEnabled = initialUser.isEnabled();
            var expectedCreatedAt = initialUser.getCreatedAt();

            // 2. Prepare environment with reset flag active and new password
            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_SEED_ENABLED", "true");
            env.setProperty("TV_DEV_RESET_PASSWORD", "true");
            env.setProperty("TV_DEV_USERNAME", "devuser");
            env.setProperty("TV_DEV_PASSWORD", "NewSecurePassword456!");
            env.setProperty("trustvault.dev.reset-password.exit-after-reset", "false");

            DevPasswordResetRunner runner = new DevPasswordResetRunner(userService, env, applicationContext);
            runner.run(null);

            // 3. Retrieve user and verify in-place update
            User updatedUser = userRepository.findByUsername("devuser").orElseThrow();

            // Invariants preserved
            assertThat(updatedUser.getId()).isEqualTo(expectedId);
            assertThat(updatedUser.getUsername()).isEqualTo("devuser");
            assertThat(updatedUser.getEmail()).isEqualTo(expectedEmail);
            assertThat(updatedUser.getRole()).isEqualTo(expectedRole);
            assertThat(updatedUser.isEnabled()).isEqualTo(expectedEnabled);
            assertThat(updatedUser.getCreatedAt()).isCloseTo(expectedCreatedAt, org.assertj.core.api.Assertions.within(1, java.time.temporal.ChronoUnit.MILLIS));

            // Password mismatch corrected: new password matches, old password does not
            assertThat(passwordEncoder.matches("NewSecurePassword456!", updatedUser.getPassword())).isTrue();
            assertThat(passwordEncoder.matches(initialRawPassword, updatedUser.getPassword())).isFalse();

            // Hash format verification: BCrypt strength 12
            assertThat(updatedUser.getPassword()).matches("^\\$2[aby]\\$12\\$[./A-Za-z0-9]{53}$");
        }

        @Test
        @DisplayName("Target restriction: attempting to reset any user other than 'devuser' must be rejected")
        void invalidTargetRejection_shouldFailSafely() {
            // Seed a different user
            userService.createUser("admin", "AdminPass123!", "admin@example.com", Role.ROLE_ADMIN);

            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_SEED_ENABLED", "true");
            env.setProperty("TV_DEV_RESET_PASSWORD", "true");
            env.setProperty("TV_DEV_USERNAME", "admin");
            env.setProperty("TV_DEV_PASSWORD", "NewAttemptedPassword999!");
            env.setProperty("trustvault.dev.reset-password.exit-after-reset", "false");

            DevPasswordResetRunner runner = new DevPasswordResetRunner(userService, env, applicationContext);

            assertThatThrownBy(() -> runner.run(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("restricted exclusively to 'devuser'");

            // Verify original password is still intact
            User admin = userRepository.findByUsername("admin").orElseThrow();
            assertThat(passwordEncoder.matches("AdminPass123!", admin.getPassword())).isTrue();
        }

        @Test
        @DisplayName("TV_DEV_SEED_ENABLED missing or false must reject the reset operation")
        void seedEnabledMissing_shouldRejectReset() {
            userService.createUser("devuser", "InitialPass123!", "devuser@trustvault.local", Role.ROLE_USER);

            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_SEED_ENABLED", "false");
            env.setProperty("TV_DEV_RESET_PASSWORD", "true");
            env.setProperty("TV_DEV_USERNAME", "devuser");
            env.setProperty("TV_DEV_PASSWORD", "NewPassword123!");
            env.setProperty("trustvault.dev.reset-password.exit-after-reset", "false");

            DevPasswordResetRunner runner = new DevPasswordResetRunner(userService, env, applicationContext);

            assertThatThrownBy(() -> runner.run(null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("TV_DEV_SEED_ENABLED must be 'true'");

            User devuser = userRepository.findByUsername("devuser").orElseThrow();
            assertThat(passwordEncoder.matches("InitialPass123!", devuser.getPassword())).isTrue();
        }

        @Test
        @DisplayName("Missing password fails safely without exposing password values")
        void missingPasswordFailsSafely() {
            userService.createUser("devuser", "InitialPass123!", "devuser@trustvault.local", Role.ROLE_USER);

            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_SEED_ENABLED", "true");
            env.setProperty("TV_DEV_RESET_PASSWORD", "true");
            env.setProperty("TV_DEV_USERNAME", "devuser");
            env.setProperty("trustvault.dev.reset-password.exit-after-reset", "false");

            DevPasswordResetRunner runner = new DevPasswordResetRunner(userService, env, applicationContext);

            assertThatThrownBy(() -> runner.run(null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("required password is missing");
        }

        @Test
        @DisplayName("Password shorter than 8 characters is rejected by validation")
        void shortPasswordIsRejected() {
            userService.createUser("devuser", "InitialPass123!", "devuser@trustvault.local", Role.ROLE_USER);

            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_SEED_ENABLED", "true");
            env.setProperty("TV_DEV_RESET_PASSWORD", "true");
            env.setProperty("TV_DEV_USERNAME", "devuser");
            env.setProperty("TV_DEV_PASSWORD", "short");
            env.setProperty("trustvault.dev.reset-password.exit-after-reset", "false");

            DevPasswordResetRunner runner = new DevPasswordResetRunner(userService, env, applicationContext);

            assertThatThrownBy(() -> runner.run(null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("at least 8 characters");
        }

        @Test
        @DisplayName("Successful reset: preserves documents, shares, and audit history")
        void successfulReset_preservesDocumentsSharesAndAuditHistory() {
            // Seed devuser and a collaborator
            User devuser = userService.createUser("devuser", "InitialPass123!", "devuser@trustvault.local", Role.ROLE_USER);
            User collaborator = userService.createUser("collab", "CollabPass123!", "collab@trustvault.local", Role.ROLE_USER);

            // Create a document owned by devuser
            Document doc = new Document("Dev Vault Secrets", "Confidential dev notes", devuser);
            doc = documentRepository.save(doc);
            Long docId = doc.getId();

            // Share document with collaborator
            DocumentShare share = new DocumentShare(doc, collaborator, SharePermission.READ);
            documentShareRepository.save(share);

            // Execute password reset
            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_SEED_ENABLED", "true");
            env.setProperty("TV_DEV_RESET_PASSWORD", "true");
            env.setProperty("TV_DEV_USERNAME", "devuser");
            env.setProperty("TV_DEV_PASSWORD", "BrandNewSecurePassword789!");
            env.setProperty("trustvault.dev.reset-password.exit-after-reset", "false");

            DevPasswordResetRunner runner = new DevPasswordResetRunner(userService, env, applicationContext);
            runner.run(null);

            // Verify password was updated
            User updated = userRepository.findByUsername("devuser").orElseThrow();
            assertThat(passwordEncoder.matches("BrandNewSecurePassword789!", updated.getPassword())).isTrue();

            // Verify document still exists and is owned by devuser
            Document retrievedDoc = documentRepository.findById(docId).orElseThrow();
            assertThat(retrievedDoc.getTitle()).isEqualTo("Dev Vault Secrets");
            assertThat(retrievedDoc.getOwner().getUsername()).isEqualTo("devuser");

            // Verify share grant is intact
            assertThat(documentShareRepository.existsByDocumentIdAndGranteeUsername(docId, "collab")).isTrue();

            // Verify audit event recorded
            List<AuditEvent> devuserAuditEvents = auditEventRepository.findByActorUsernameOrderByTimestampDesc("devuser");
            assertThat(devuserAuditEvents).anyMatch(e -> e.getAction() == AuditAction.PASSWORD_CHANGE);
        }

        @Test
        @DisplayName("exit-after-reset default (true) initiates asynchronous shutdown on ConfigurableApplicationContext")
        void exitAfterResetDefault_initiatesShutdown() throws InterruptedException {
            userService.createUser("devuser", "InitialPass123!", "devuser@trustvault.local", Role.ROLE_USER);

            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_SEED_ENABLED", "true");
            env.setProperty("TV_DEV_RESET_PASSWORD", "true");
            env.setProperty("TV_DEV_USERNAME", "devuser");
            env.setProperty("TV_DEV_PASSWORD", "NewPassword123!");
            // Note: exit-after-reset is omitted so default (true) is tested

            CountDownLatch latch = new CountDownLatch(1);
            ConfigurableApplicationContext mockCac = Mockito.mock(ConfigurableApplicationContext.class);
            Mockito.doAnswer(inv -> {
                latch.countDown();
                return null;
            }).when(mockCac).close();

            DevPasswordResetRunner runner = new DevPasswordResetRunner(userService, env, mockCac);
            runner.run(null);

            // Verify the asynchronous shutdown thread invoked close()
            boolean shutdownTriggered = latch.await(2, TimeUnit.SECONDS);
            assertThat(shutdownTriggered).isTrue();
        }
    }
}
