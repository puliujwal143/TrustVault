package com.trustvault.config;

import com.trustvault.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Dedicated one-shot development runner that resets the password of the existing 'devuser' account.
 *
 * Security Requirements & Strict Invariants:
 * 1. Strictly gated: ONLY active when Spring profile is explicitly 'dev' AND property
 *    'trustvault.dev.reset-password.enabled' is 'true' (TV_DEV_RESET_PASSWORD=true).
 * 2. Requires 'trustvault.dev.seed-user.enabled' (TV_DEV_SEED_ENABLED=true) to be active.
 * 3. Never runs in production.
 * 4. Never hardcodes, prints, or logs plaintext passwords or password hashes.
 * 5. Target username is restricted strictly to 'devuser'. Rejects any other account.
 * 6. Updates the existing account in place; preserves id, role, email, enabled status,
 *    documents, shares, and audit history.
 * 7. One-shot execution: After completing the reset, initiates a clean application shutdown
 *    so the application does not continue running with the reset flag active.
 *    (Shutdown behavior can be disabled in test environments via trustvault.dev.reset-password.exit-after-reset=false).
 */
@Component
@Profile("dev")
@ConditionalOnProperty(name = "trustvault.dev.reset-password.enabled", havingValue = "true", matchIfMissing = false)
@Order(50)
public class DevPasswordResetRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DevPasswordResetRunner.class);

    private final UserService userService;
    private final Environment environment;
    private final ApplicationContext applicationContext;

    public DevPasswordResetRunner(
            UserService userService,
            Environment environment,
            ApplicationContext applicationContext) {
        this.userService = userService;
        this.environment = environment;
        this.applicationContext = applicationContext;
    }

    @Override
    public void run(ApplicationArguments args) {
        log.info("TrustVault Development Password Reset Runner is active ('dev' profile + reset-password.enabled=true).");

        // Guard 1: Require TV_DEV_SEED_ENABLED=true
        String seedEnabled = resolveProperty("trustvault.dev.seed-user.enabled", "TV_DEV_SEED_ENABLED");
        if (!"true".equalsIgnoreCase(seedEnabled)) {
            throw new IllegalStateException("Development password reset rejected: TV_DEV_SEED_ENABLED must be 'true'.");
        }

        // Guard 2: Resolve and validate target username (must strictly be 'devuser')
        String username = resolveProperty("trustvault.dev.seed-user.username", "TV_DEV_USERNAME");
        if (username == null || username.trim().isBlank()) {
            username = "devuser";
        }
        String trimmedUsername = username.trim();
        if (!"devuser".equals(trimmedUsername)) {
            log.error("Development password reset rejected: target username '{}' is not permitted. Only 'devuser' can be reset.", trimmedUsername);
            throw new IllegalArgumentException("Development password reset is restricted exclusively to 'devuser'");
        }

        // Guard 3: Resolve new password from environment variable
        String password = resolveProperty("trustvault.dev.seed-user.password", "TV_DEV_PASSWORD");
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("Development password reset failed: required password is missing. " +
                    "Set TV_DEV_PASSWORD environment variable.");
        }

        try {
            userService.resetDevUserPassword(trimmedUsername, password);
            log.info("================================================================================");
            log.info("[SUCCESS] One-shot password reset for development user '{}' completed successfully.", trimmedUsername);
            log.info("All active sessions revoked. The account's ID, email, role, and data were preserved.");
            log.info("================================================================================");
        } catch (Exception ex) {
            String safeDetail = sanitizeExceptionMessage(ex, "password reset failed");
            log.error("Failed to reset password for development user '{}' [{}]: {}", trimmedUsername, ex.getClass().getSimpleName(), safeDetail);
            throw new IllegalStateException("Failed to reset development test user password: " + safeDetail, ex);
        }

        // One-shot safeguard: initiate clean application context shutdown
        boolean exitAfterReset = Boolean.parseBoolean(
                resolveProperty("trustvault.dev.reset-password.exit-after-reset", "TV_DEV_RESET_EXIT_AFTER"));
        // Default to true if not explicitly set to false
        String exitProp = environment.getProperty("trustvault.dev.reset-password.exit-after-reset");
        if (exitProp == null) {
            exitAfterReset = true;
        }

        if (exitAfterReset && applicationContext instanceof ConfigurableApplicationContext cac) {
            log.info("Initiating one-shot shutdown. Start the application normally without TV_DEV_RESET_PASSWORD.");
            initiateShutdown(cac);
        }
    }

    /**
     * Initiates asynchronous application shutdown on a dedicated daemon thread.
     * This ensures the current ApplicationRunner execution finishes cleanly and
     * allows SpringApplication.run() to return before the context teardown commences.
     *
     * @param cac configurable application context to close
     */
    protected void initiateShutdown(ConfigurableApplicationContext cac) {
        Thread shutdownThread = new Thread(() -> {
            try {
                Thread.sleep(100);
                cac.close();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "dev-reset-shutdown-thread");
        shutdownThread.setDaemon(true);
        shutdownThread.start();
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
