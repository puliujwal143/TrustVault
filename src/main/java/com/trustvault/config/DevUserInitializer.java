package com.trustvault.config;

import com.trustvault.entity.Role;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Development-only database initializer that seeds a local test user account.
 *
 * Security Requirements & Strict Invariants:
 * 1. Strictly gated: ONLY active when Spring profile is explicitly 'dev' AND property
 *    'trustvault.dev.seed-user.enabled' is 'true'. The default is disabled.
 * 2. Never runs in production.
 * 3. Never hardcodes credentials or logs passwords in plaintext.
 * 4. Resolves credentials strictly from environment variables:
 *    - TV_DEV_USERNAME (or trustvault.dev.seed-user.username)
 *    - TV_DEV_PASSWORD (or trustvault.dev.seed-user.password)
 *    - TV_DEV_EMAIL    (or trustvault.dev.seed-user.email)
 * 5. Uses production UserService.createUser(...) to ensure BCrypt (strength 12)
 *    hashing, format validation, and transactional audit recording.
 * 6. Strictly assigns Role.ROLE_USER.
 * 7. Idempotent: If the username already exists, logs a safe informational message
 *    and does not modify or overwrite existing credentials.
 * 8. Fails safely with clear errors if required variables are missing or invalid,
 *    never printing or exposing password values.
 */
@Component
@Profile("dev")
@ConditionalOnProperty(name = "trustvault.dev.seed-user.enabled", havingValue = "true", matchIfMissing = false)
@Order(100)
public class DevUserInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DevUserInitializer.class);

    private final UserService userService;
    private final UserRepository userRepository;
    private final Environment environment;

    public DevUserInitializer(
            UserService userService,
            UserRepository userRepository,
            Environment environment) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.environment = environment;
    }

    @Override
    public void run(ApplicationArguments args) {
        log.info("TrustVault Development User Initializer is active ('dev' profile + seed-user.enabled=true).");

        String username = resolveProperty("trustvault.dev.seed-user.username", "TV_DEV_USERNAME");
        String password = resolveProperty("trustvault.dev.seed-user.password", "TV_DEV_PASSWORD");
        String email = resolveProperty("trustvault.dev.seed-user.email", "TV_DEV_EMAIL");

        if (username == null || username.trim().isBlank()) {
            throw new IllegalStateException("Development user initialization failed: required username is missing. " +
                    "Set TV_DEV_USERNAME environment variable.");
        }
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("Development user initialization failed: required password is missing. " +
                    "Set TV_DEV_PASSWORD environment variable.");
        }
        if (email == null || email.trim().isBlank()) {
            throw new IllegalStateException("Development user initialization failed: required email is missing. " +
                    "Set TV_DEV_EMAIL environment variable.");
        }

        String trimmedUsername = username.trim();
        String trimmedEmail = email.trim();

        // Idempotency: if user already exists, never modify or reset existing password
        if (userRepository.existsByUsername(trimmedUsername)) {
            log.info("Development user '{}' already exists in local database; skipping creation.", trimmedUsername);
            return;
        }

        if (userRepository.existsByEmail(trimmedEmail)) {
            log.warn("An account with email '{}' already exists; skipping development user creation.", trimmedEmail);
            return;
        }

        try {
            userService.createUser(trimmedUsername, password, trimmedEmail, Role.ROLE_USER);
            log.info("Development test user '{}' successfully created with role '{}'.", trimmedUsername, Role.ROLE_USER);
        } catch (Exception ex) {
            String safeDetail = sanitizeExceptionMessage(ex, "provisioning failed");
            log.error("Failed to create development user '{}' [{}]: {}", trimmedUsername, ex.getClass().getSimpleName(), safeDetail);
            throw new IllegalStateException("Failed to create development test user: " + safeDetail, ex);
        }
    }

    private String sanitizeExceptionMessage(Exception ex, String defaultMessage) {
        if (ex instanceof IllegalArgumentException && ex.getMessage() != null) {
            return ex.getMessage().replaceAll("[\r\n]", " ").trim();
        }
        return defaultMessage;
    }

    private String resolveProperty(String propertyKey, String envVarKey) {
        String value = environment.getProperty(propertyKey);
        if (value != null && !value.isBlank()) {
            return value;
        }
        return environment.getProperty(envVarKey);
    }
}
