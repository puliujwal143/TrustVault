package com.trustvault.config;

import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit and integration tests for DevUserInitializer:
 * - Disabled by default when 'dev' profile or property is missing.
 * - Missing credentials fail safely without exposing values.
 * - Successful creation with valid credentials and Role.ROLE_USER.
 * - Idempotency: does not overwrite existing users.
 */
class DevUserInitializerTest {

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.seed-user.enabled=false",
            "spring.profiles.active=default"
    })
    @ActiveProfiles("default")
    @DisplayName("1. Disabled by Default Verification")
    class DisabledByDefaultTest {

        @Autowired
        private ApplicationContext applicationContext;

        @Test
        @DisplayName("DevUserInitializer bean must NOT be present when 'dev' profile and seed-user property are absent")
        void beanNotLoadedByDefault() {
            assertThat(applicationContext.containsBean("devUserInitializer")).isFalse();
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.seed-user.enabled=false"
    })
    @ActiveProfiles("dev")
    @DisplayName("2. Profile-Only Verification (property still disabled)")
    class ProfileOnlyWithoutPropertyTest {

        @Autowired
        private ApplicationContext applicationContext;

        @Test
        @DisplayName("DevUserInitializer bean must NOT be present when 'dev' profile is active but seed-user.enabled is false or missing")
        void beanNotLoadedWithoutProperty() {
            assertThat(applicationContext.containsBean("devUserInitializer")).isFalse();
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.seed-user.enabled=true",
            "spring.profiles.active=default"
    })
    @ActiveProfiles("default")
    @DisplayName("3. Property-Only Without Dev Profile Verification")
    class PropertyOnlyWithoutDevProfileTest {

        @Autowired
        private ApplicationContext applicationContext;

        @Test
        @DisplayName("DevUserInitializer bean must NOT be present when seed-user.enabled is true but 'dev' profile is absent")
        void beanNotLoadedWithoutDevProfile() {
            assertThat(applicationContext.containsBean("devUserInitializer")).isFalse();
        }
    }

    @Nested
    @SpringBootTest(properties = {
            "trustvault.dev.seed-user.enabled=false"
    })
    @DisplayName("4. Execution Logic & Security Invariants")
    class ExecutionLogicTest {

        @Autowired
        private UserService userService;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @BeforeEach
        void setUp() {
            userRepository.deleteAll();
        }

        @Test
        @DisplayName("Missing username fails safely with clear message")
        void missingUsernameFailsSafely() {
            MockEnvironment env = new MockEnvironment();
            env.setProperty("trustvault.dev.seed-user.password", "ValidPass123!");
            env.setProperty("trustvault.dev.seed-user.email", "dev@example.com");

            DevUserInitializer initializer = new DevUserInitializer(userService, userRepository, env);

            assertThatThrownBy(() -> initializer.run(null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("required username is missing");
        }

        @Test
        @DisplayName("Missing password fails safely with clear message and never prints password")
        void missingPasswordFailsSafely() {
            MockEnvironment env = new MockEnvironment();
            env.setProperty("trustvault.dev.seed-user.username", "testuser");
            env.setProperty("trustvault.dev.seed-user.email", "dev@example.com");

            DevUserInitializer initializer = new DevUserInitializer(userService, userRepository, env);

            assertThatThrownBy(() -> initializer.run(null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("required password is missing")
                    .satisfies(t -> assertThat(t.getMessage()).doesNotContain("ValidPass123!"));
        }

        @Test
        @DisplayName("Missing email fails safely with clear message")
        void missingEmailFailsSafely() {
            MockEnvironment env = new MockEnvironment();
            env.setProperty("trustvault.dev.seed-user.username", "testuser");
            env.setProperty("trustvault.dev.seed-user.password", "ValidPass123!");

            DevUserInitializer initializer = new DevUserInitializer(userService, userRepository, env);

            assertThatThrownBy(() -> initializer.run(null))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("required email is missing");
        }

        @Test
        @DisplayName("Valid credentials creates user with Role.ROLE_USER and BCrypt password")
        void successfulUserCreation() {
            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_USERNAME", "developer");
            env.setProperty("TV_DEV_PASSWORD", "SuperSecurePassword123!");
            env.setProperty("TV_DEV_EMAIL", "developer@example.com");

            DevUserInitializer initializer = new DevUserInitializer(userService, userRepository, env);
            initializer.run(null);

            User user = userRepository.findByUsername("developer").orElseThrow();
            assertThat(user.getUsername()).isEqualTo("developer");
            assertThat(user.getEmail()).isEqualTo("developer@example.com");
            assertThat(user.getRole()).isEqualTo(Role.ROLE_USER);
            assertThat(user.isEnabled()).isTrue();
            assertThat(passwordEncoder.matches("SuperSecurePassword123!", user.getPassword())).isTrue();
        }

        @Test
        @DisplayName("Idempotency: existing user is not modified or password reset")
        void existingUserNotOverwritten() {
            // Create user initially with original password
            userService.createUser("existingdev", "OriginalPassword123!", "existing@example.com", Role.ROLE_USER);

            // Attempt to seed same username with a different password
            MockEnvironment env = new MockEnvironment();
            env.setProperty("TV_DEV_USERNAME", "existingdev");
            env.setProperty("TV_DEV_PASSWORD", "AttemptedNewPassword999!");
            env.setProperty("TV_DEV_EMAIL", "existing@example.com");

            DevUserInitializer initializer = new DevUserInitializer(userService, userRepository, env);
            // Should exit gracefully without throwing
            initializer.run(null);

            // Verify original password is still intact
            User user = userRepository.findByUsername("existingdev").orElseThrow();
            assertThat(passwordEncoder.matches("OriginalPassword123!", user.getPassword())).isTrue();
            assertThat(passwordEncoder.matches("AttemptedNewPassword999!", user.getPassword())).isFalse();
        }
    }
}
