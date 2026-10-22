package com.trustvault.service;

import com.trustvault.audit.AuditAction;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Internal business service managing user accounts and session lifecycle.
 *
 * Security Requirements:
 * - Passwords MUST be hashed using the configured PasswordEncoder (BCrypt) before persistence.
 * - Plaintext passwords are NEVER logged, printed, or stored.
 * - Enforces 3-50 character length constraint on usernames.
 * - Trims usernames and normalizes emails consistently across all creation and lookup operations.
 * - Treats database unique constraints as the final authoritative defense against concurrent race conditions.
 * - Routine logs NEVER expose raw SQL exceptions, database column names, or internal stack traces.
 * - Active sessions are deliberately revoked upon password changes via the SessionRegistry.
 * - Strictly internal service; does NOT expose an unauthenticated public registration endpoint.
 * - Emits structured audit events on password change, deactivation, and reactivation within the same transaction.
 */
@Service
@Transactional
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionRegistry sessionRegistry;
    private final AuditService auditService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, SessionRegistry sessionRegistry) {
        this(userRepository, passwordEncoder, sessionRegistry, null);
    }

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, SessionRegistry sessionRegistry, AuditService auditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionRegistry = sessionRegistry;
        this.auditService = auditService;
    }

    /**
     * Creates and persists a new user account with a BCrypt-hashed password.
     *
     * Validates input constraints, hashes the password, and protects against
     * concurrent duplicate creation using both proactive checks and database
     * unique constraint enforcement.
     *
     * @param username    Unique account username (3-50 characters)
     * @param rawPassword Plaintext password to be hashed (min 8 characters, never stored)
     * @param email       Unique email address
     * @param role        Assigned role (ROLE_USER, ROLE_ADMIN)
     * @return The persisted User entity containing the hashed password
     * @throws IllegalArgumentException if inputs are invalid or account already exists
     * @throws IllegalStateException    if an unexpected database constraint error occurs
     */
    public User createUser(String username, String rawPassword, String email, Role role) {
        Objects.requireNonNull(username, "Username must not be null");
        Objects.requireNonNull(rawPassword, "Password must not be null");
        Objects.requireNonNull(email, "Email must not be null");
        Objects.requireNonNull(role, "Role must not be null");

        String trimmedUsername = username.trim();
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        // Enforce 3-50 character username constraint matching User entity schema
        if (trimmedUsername.length() < 3 || trimmedUsername.length() > 50) {
            throw new IllegalArgumentException("Username must be between 3 and 50 characters: '" + trimmedUsername + "'");
        }

        if (rawPassword.isBlank() || rawPassword.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }

        if (normalizedEmail.isBlank()) {
            throw new IllegalArgumentException("Email must not be blank");
        }

        // Proactive application-level uniqueness checks
        if (userRepository.existsByUsername(trimmedUsername)) {
            throw new IllegalArgumentException("Username is already in use: " + trimmedUsername);
        }
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException("Email is already registered: " + normalizedEmail);
        }

        // Securely hash password using BCrypt with configured work factor (12)
        String hashedPassword = passwordEncoder.encode(rawPassword);

        User user = new User(trimmedUsername, hashedPassword, normalizedEmail, role);

        try {
            // saveAndFlush ensures database constraints are evaluated immediately within this try block,
            // catching concurrent race condition collisions that pass proactive checks simultaneously.
            User savedUser = userRepository.saveAndFlush(user);

            // Audit log strictly logs username and role - NEVER the password
            log.info("Created user account for username '{}' with role '{}'", savedUser.getUsername(), savedUser.getRole());

            return savedUser;
        } catch (DataIntegrityViolationException ex) {
            // Distinguish expected uniqueness violations from other integrity failures without leaking raw SQL
            boolean isUniquenessViolation = isDuplicateConstraintViolation(trimmedUsername, normalizedEmail, ex);

            if (isUniquenessViolation) {
                // Log safe sanitized message - NEVER raw ex.getMessage() with SQL details
                log.warn("Account creation rejected: unique constraint violation for username '{}'", trimmedUsername);
                throw new IllegalArgumentException("Account with username '" + trimmedUsername + "' or email '" + normalizedEmail + "' already exists");
            } else {
                log.error("Database integrity failure during account creation for username '{}'", trimmedUsername);
                log.debug("Database integrity failure details (debug only)", ex);
                throw new IllegalStateException("Account creation failed due to an unexpected database constraint error");
            }
        }
    }

    /**
     * Changes an existing user's password securely and revokes all active sessions.
     *
     * Validates current credentials against the stored BCrypt hash, validates new password
     * complexity, hashes the new password with BCrypt before persistence, and revokes all
     * active sessions across all devices to prevent unauthorized access with old sessions.
     *
     * @param username           Username of the account
     * @param rawCurrentPassword The current password for verification (never stored/logged)
     * @param rawNewPassword     The new password to set (never stored/logged)
     * @throws IllegalArgumentException if user is not found, current password is invalid, or new password is invalid
     */
    public void changePassword(String username, String rawCurrentPassword, String rawNewPassword) {
        Objects.requireNonNull(username, "Username must not be null");
        Objects.requireNonNull(rawCurrentPassword, "Current password must not be null");
        Objects.requireNonNull(rawNewPassword, "New password must not be null");

        String trimmedUsername = username.trim();
        User user = userRepository.findByUsername(trimmedUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + trimmedUsername));

        if (!passwordEncoder.matches(rawCurrentPassword, user.getPassword())) {
            throw new IllegalArgumentException("Current password does not match");
        }

        if (rawNewPassword.isBlank() || rawNewPassword.length() < 8) {
            throw new IllegalArgumentException("New password must be at least 8 characters");
        }

        String hashedNewPassword = passwordEncoder.encode(rawNewPassword);
        user.setPassword(hashedNewPassword);
        userRepository.save(user);

        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.PASSWORD_CHANGE,
                    user.getUsername(),
                    null,
                    null,
                    null,
                    null,
                    null
            );
        }

        // Security Policy: Invalidate all active sessions for this user ONLY after the password update transaction successfully commits
        scheduleSessionRevocationAfterCommit(user.getUsername());

        log.info("Password successfully changed for user '{}'", user.getUsername());
    }

    /**
     * Resets a development user's password in place using BCrypt (strength 12),
     * revoking all active sessions post-commit, and emitting an audit event.
     *
     * Security Invariants & In-Place Mutation:
     * - Strictly restricted to username 'devuser'. Rejects any other username.
     * - Updates only the password hash; preserves id, role, email, enabled status, and createdAt.
     * - Requires minimum 8 characters; never prints or logs the raw password or password hash.
     * - Emits structured AuditAction.PASSWORD_CHANGE within the same transaction.
     * - Revokes active sessions post-commit via scheduleSessionRevocationAfterCommit.
     *
     * @param username       Username of the development account (must be 'devuser')
     * @param rawNewPassword The new plaintext password to hash and set (min 8 characters, never logged)
     * @throws IllegalArgumentException if user is not found, username is not 'devuser', or password is invalid
     */
    public void resetDevUserPassword(String username, String rawNewPassword) {
        Objects.requireNonNull(username, "Username must not be null");
        Objects.requireNonNull(rawNewPassword, "Password must not be null");

        String trimmedUsername = username.trim();
        if (!"devuser".equals(trimmedUsername)) {
            throw new IllegalArgumentException("Development password reset is restricted exclusively to 'devuser'");
        }

        if (rawNewPassword.isBlank() || rawNewPassword.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }

        User user = userRepository.findByUsername(trimmedUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + trimmedUsername));

        String hashedPassword = passwordEncoder.encode(rawNewPassword);
        user.setPassword(hashedPassword);
        userRepository.save(user);

        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.PASSWORD_CHANGE,
                    user.getUsername(),
                    null,
                    null,
                    null,
                    null,
                    null
            );
        }

        // Security Policy: Invalidate all active sessions for this user ONLY after the password update transaction successfully commits
        scheduleSessionRevocationAfterCommit(user.getUsername());

        log.info("Password successfully reset for development user '{}'", user.getUsername());
    }

    /**
     * Deactivates an existing user account and revokes all active sessions post-commit.
     *
     * @param username Username of the account to deactivate
     * @throws IllegalArgumentException if user is not found
     */
    public void deactivateUser(String username) {
        Objects.requireNonNull(username, "Username must not be null");
        String trimmedUsername = username.trim();
        User user = userRepository.findByUsername(trimmedUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + trimmedUsername));

        if (!user.isEnabled()) {
            log.debug("User '{}' is already deactivated", user.getUsername());
            return;
        }

        user.setEnabled(false);
        userRepository.save(user);

        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.USER_DEACTIVATE,
                    trimmedUsername,
                    null,
                    null,
                    user.getUsername(),
                    null,
                    null
            );
        }

        // Security Policy: Invalidate all active sessions for this user ONLY after the deactivation transaction commits
        scheduleSessionRevocationAfterCommit(user.getUsername());

        log.info("User account '{}' successfully deactivated and active sessions scheduled for revocation", user.getUsername());
    }

    /**
     * Reactivates a previously disabled user account.
     *
     * @param username Username of the account to reactivate
     * @throws IllegalArgumentException if user is not found
     */
    public void reactivateUser(String username) {
        Objects.requireNonNull(username, "Username must not be null");
        String trimmedUsername = username.trim();
        User user = userRepository.findByUsername(trimmedUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + trimmedUsername));

        if (user.isEnabled()) {
            log.debug("User '{}' is already active", user.getUsername());
            return;
        }

        user.setEnabled(true);
        userRepository.save(user);

        if (auditService != null) {
            auditService.recordSuccess(
                    AuditAction.USER_REACTIVATE,
                    trimmedUsername,
                    null,
                    null,
                    user.getUsername(),
                    null,
                    null
            );
        }

        log.info("User account '{}' successfully reactivated", user.getUsername());
    }

    /**
     * Schedules session revocation for the specified user after the current transaction successfully commits.
     *
     * If an active transaction synchronization is available, revocation is registered via
     * TransactionSynchronization.afterCommit(). If no transaction synchronization is active,
     * revocation executes immediately to avoid silently bypassing security revocation.
     * Checks existing synchronizations to prevent duplicate registrations within the same transaction.
     *
     * @param username the username whose sessions should be invalidated
     */
    private void scheduleSessionRevocationAfterCommit(String username) {
        String normalizedUsername = username.trim();
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            UserSessionRevocationSynchronization sync = new UserSessionRevocationSynchronization(normalizedUsername, this);
            if (!TransactionSynchronizationManager.getSynchronizations().contains(sync)) {
                TransactionSynchronizationManager.registerSynchronization(sync);
                log.debug("Registered post-commit session revocation synchronization for user '{}'", normalizedUsername);
            } else {
                log.debug("Session revocation synchronization already registered for user '{}' in current transaction", normalizedUsername);
            }
        } else {
            log.warn("Transaction synchronization is not active; revoking sessions immediately for user '{}'", normalizedUsername);
            revokeAllUserSessions(normalizedUsername);
        }
    }

    /**
     * TransactionSynchronization that triggers session revocation only after transaction commit.
     * Implements equals/hashCode based on username to prevent duplicate registrations within the same transaction.
     */
    public static class UserSessionRevocationSynchronization implements TransactionSynchronization {
        private final String username;
        private final UserService userService;

        public UserSessionRevocationSynchronization(String username, UserService userService) {
            this.username = username;
            this.userService = userService;
        }

        @Override
        public void afterCommit() {
            userService.revokeAllUserSessions(username);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof UserSessionRevocationSynchronization that)) return false;
            return username.equalsIgnoreCase(that.username);
        }

        @Override
        public int hashCode() {
            return username.toLowerCase(Locale.ROOT).hashCode();
        }

        @Override
        public String toString() {
            return "UserSessionRevocationSynchronization[" + username + "]";
        }
    }

    /**
     * Revokes all active authenticated sessions for the given user.
     *
     * Marks every session registered in SessionRegistry for this username as expired,
     * triggering immediate session termination on subsequent requests.
     *
     * @param username the username whose sessions should be invalidated
     */
    public void revokeAllUserSessions(String username) {
        revokeOtherUserSessions(username, null);
    }

    /**
     * Revokes all active sessions for a user, optionally preserving a specified session ID.
     *
     * @param username               the username whose sessions should be invalidated
     * @param currentSessionIdToKeep the session ID to preserve (or null to revoke all sessions)
     */
    public void revokeOtherUserSessions(String username, String currentSessionIdToKeep) {
        if (sessionRegistry == null || username == null) {
            return;
        }

        String normalizedUsername = username.trim();

        for (Object principal : sessionRegistry.getAllPrincipals()) {
            if (principal instanceof UserDetails userDetails && userDetails.getUsername().equalsIgnoreCase(normalizedUsername)) {
                List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, false);
                for (SessionInformation sessionInfo : sessions) {
                    if (currentSessionIdToKeep == null || !sessionInfo.getSessionId().equals(currentSessionIdToKeep)) {
                        sessionInfo.expireNow();
                        log.info("Revoked active session for user '{}'", normalizedUsername);
                    }
                }
            }
        }
    }

    /**
     * Helper to determine whether a DataIntegrityViolationException is caused by a unique constraint.
     */
    private boolean isDuplicateConstraintViolation(String username, String email, DataIntegrityViolationException ex) {
        // First check: did another concurrent transaction commit this username or email?
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            return true;
        }

        // Second check: inspect exception causes for standard unique constraint markers without exposing to caller
        Throwable rootCause = ex.getMostSpecificCause();
        if (rootCause != null && rootCause.getMessage() != null) {
            String message = rootCause.getMessage().toLowerCase(Locale.ROOT);
            return message.contains("unique") || message.contains("duplicate") || message.contains("23505");
        }

        return false;
    }

    /**
     * Finds a user by their username (trimmed consistently).
     *
     * @param username the username to look up
     * @return Optional containing the User if found
     */
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return userRepository.findByUsername(username.trim());
    }

    /**
     * Finds a user by their email (normalized consistently to lowercase).
     *
     * @param email the email to look up
     * @return Optional containing the User if found
     */
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        if (email == null) {
            return Optional.empty();
        }
        return userRepository.findByEmail(email.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * Checks if a username is already taken (trimmed consistently).
     *
     * @param username the username to check
     * @return true if taken
     */
    @Transactional(readOnly = true)
    public boolean existsByUsername(String username) {
        if (username == null) {
            return false;
        }
        return userRepository.existsByUsername(username.trim());
    }

    /**
     * Checks if an email is already registered (normalized consistently).
     *
     * @param email the email to check
     * @return true if registered
     */
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        if (email == null) {
            return false;
        }
        return userRepository.existsByEmail(email.trim().toLowerCase(Locale.ROOT));
    }
}
