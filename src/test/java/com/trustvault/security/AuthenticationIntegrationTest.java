package com.trustvault.security;

import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SessionRegistry sessionRegistry;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired(required = false)
    private com.trustvault.repository.DocumentShareRepository documentShareRepository;

    @Autowired(required = false)
    private com.trustvault.repository.DocumentRepository documentRepository;

    @BeforeEach
    void setUp() {
        if (documentShareRepository != null) {
            documentShareRepository.deleteAll();
        }
        if (documentRepository != null) {
            documentRepository.deleteAll();
        }
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Valid credentials should authenticate via form login and establish session")
    void validLogin_withFormLogin_shouldAuthenticateSuccessfully() throws Exception {
        userService.createUser("alice", "SecurePass123!", "alice@example.com", Role.ROLE_USER);

        mockMvc.perform(formLogin().user("alice").password("SecurePass123!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername("alice").withRoles("USER"));
    }

    @Test
    @DisplayName("Invalid password should fail authentication and redirect to login error")
    void invalidCredentials_withFormLogin_shouldFailAuthentication() throws Exception {
        userService.createUser("bob", "CorrectPass123!", "bob@example.com", Role.ROLE_USER);

        mockMvc.perform(formLogin().user("bob").password("IncorrectPass999!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("Disabled user account must be rejected during authentication")
    void disabledUser_shouldBeRejectedDuringAuthentication() throws Exception {
        User disabledUser = new User("charlie", passwordEncoder.encode("Password123!"), "charlie@example.com", Role.ROLE_USER);
        disabledUser.setEnabled(false);
        userRepository.save(disabledUser);

        mockMvc.perform(formLogin().user("charlie").password("Password123!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("User passwords must be securely hashed with BCrypt and never stored in plaintext")
    void passwordHashing_shouldStoreBCryptHashAndNeverPlaintext() {
        String rawPassword = "MySecretPassword123!";
        User createdUser = userService.createUser("diana", rawPassword, "diana@example.com", Role.ROLE_USER);

        User retrievedUser = userRepository.findByUsername("diana").orElseThrow();

        // Verify password is NOT stored as plaintext
        assertThat(retrievedUser.getPassword()).isNotEqualTo(rawPassword);

        // Verify BCrypt format: starts with $2a$, $2b$, or $2y$ followed by cost factor (12)
        assertThat(retrievedUser.getPassword()).matches("^\\$2[aby]\\$12\\$[./A-Za-z0-9]{53}$");

        // Verify PasswordEncoder validates the raw password against the stored hash
        assertThat(passwordEncoder.matches(rawPassword, retrievedUser.getPassword())).isTrue();
        assertThat(passwordEncoder.matches("WrongPassword!", retrievedUser.getPassword())).isFalse();
    }

    @Test
    @DisplayName("Duplicate username or email must be rejected by UserService")
    void duplicateUserCreation_shouldBeRejected() {
        userService.createUser("edward", "Password123!", "edward@example.com", Role.ROLE_USER);

        // Duplicate username
        assertThatThrownBy(() -> userService.createUser("edward", "DifferentPass123!", "other@example.com", Role.ROLE_USER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username is already in use");

        // Duplicate email
        assertThatThrownBy(() -> userService.createUser("edward2", "DifferentPass123!", "edward@example.com", Role.ROLE_USER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Email is already registered");
    }

    @Test
    @DisplayName("Username length validation: <3 chars and >50 chars must be rejected")
    void usernameLengthValidation_shouldEnforceThreeToFiftyCharacters() {
        // Less than 3 characters
        assertThatThrownBy(() -> userService.createUser("ab", "Password123!", "ab@example.com", Role.ROLE_USER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username must be between 3 and 50 characters");

        // Greater than 50 characters (51 chars)
        String longUsername = "a".repeat(51);
        assertThatThrownBy(() -> userService.createUser(longUsername, "Password123!", "long@example.com", Role.ROLE_USER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Username must be between 3 and 50 characters");

        // Boundary: exactly 3 characters (valid)
        User minUser = userService.createUser("xyz", "Password123!", "xyz@example.com", Role.ROLE_USER);
        assertThat(minUser.getUsername()).isEqualTo("xyz");

        // Boundary: exactly 50 characters (valid)
        String maxUsername = "b".repeat(50);
        User maxUser = userService.createUser(maxUsername, "Password123!", "max@example.com", Role.ROLE_USER);
        assertThat(maxUser.getUsername()).isEqualTo(maxUsername);
    }

    @Test
    @DisplayName("Whitespace handling: leading and trailing whitespace must be trimmed consistently")
    void whitespaceHandling_shouldTrimUsernames() throws Exception {
        userService.createUser("  frank  ", "Password123!", "frank@example.com", Role.ROLE_USER);

        // Saved username should be trimmed
        User user = userService.findByUsername("frank").orElseThrow();
        assertThat(user.getUsername()).isEqualTo("frank");

        // Login using trimmed username should succeed
        mockMvc.perform(formLogin().user("frank").password("Password123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("frank"));

        // Blank or whitespace-only username must be rejected
        assertThatThrownBy(() -> userService.createUser("   ", "Password123!", "blank@example.com", Role.ROLE_USER))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Email normalization: mixed-case emails must be normalized to lowercase")
    void emailNormalization_shouldStoreAndQueryInLowercase() {
        userService.createUser("george", "Password123!", "George.Miller@EXAMPLE.Com", Role.ROLE_USER);

        User user = userService.findByUsername("george").orElseThrow();
        assertThat(user.getEmail()).isEqualTo("george.miller@example.com");

        // Lookup by uppercase/mixed-case email succeeds
        assertThat(userService.findByEmail("GEORGE.MILLER@EXAMPLE.COM")).isPresent();
        assertThat(userService.existsByEmail("george.miller@EXAMPLE.COM")).isTrue();

        // Duplicate check with alternate case is rejected
        assertThatThrownBy(() -> userService.createUser("george2", "Password123!", "george.miller@example.com", Role.ROLE_USER))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Email is already registered");
    }

    @Test
    @DisplayName("Password change: should verify old password, enforce length, hash with BCrypt, and update login")
    void changePassword_shouldVerifyOldPasswordAndAllowNewLogin() throws Exception {
        userService.createUser("helen", "OldPassword123!", "helen@example.com", Role.ROLE_USER);

        // Attempt change with incorrect current password
        assertThatThrownBy(() -> userService.changePassword("helen", "WrongCurrentPassword!", "NewPassword123!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Current password does not match");

        // Attempt change with new password that is too short
        assertThatThrownBy(() -> userService.changePassword("helen", "OldPassword123!", "short"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("New password must be at least 8 characters");

        // Successful password change
        userService.changePassword("helen", "OldPassword123!", "NewPassword123!");

        // Old password no longer authenticates
        mockMvc.perform(formLogin().user("helen").password("OldPassword123!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());

        // New password authenticates successfully
        mockMvc.perform(formLogin().user("helen").password("NewPassword123!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername("helen"));
    }

    @Test
    @DisplayName("JPA lifecycle safety: equals and hashCode based on natural key remain invariant across persist")
    void jpaLifecycleSafety_naturalKeyEqualsAndHashCode_shouldRemainConsistentAcrossPersist() {
        // Transient entity (id is null)
        User transientUser = new User("ian", passwordEncoder.encode("Password123!"), "ian@example.com", Role.ROLE_USER);
        assertThat(transientUser.getId()).isNull();

        Set<User> userSet = new HashSet<>();
        userSet.add(transientUser);

        // Before persist: set contains transient user
        assertThat(userSet).contains(transientUser);

        // Persist entity to database (id is now generated and assigned)
        User persistedUser = userRepository.saveAndFlush(transientUser);
        assertThat(persistedUser.getId()).isNotNull();

        // After persist: set must STILL contain the user!
        // This verifies that hashCode and equals did not mutate when id was generated.
        assertThat(userSet).contains(persistedUser);
        assertThat(userSet).contains(transientUser);
        assertThat(transientUser).isEqualTo(persistedUser);
    }

    @Test
    @DisplayName("Password change must revoke active sessions in SessionRegistry")
    void passwordChange_shouldRevokeActiveSessionsInSessionRegistry() throws Exception {
        userService.createUser("jack", "OldPassword123!", "jack@example.com", Role.ROLE_USER);

        // Authenticate via form login to establish an active session in SessionRegistry
        MvcResult loginResult = mockMvc.perform(formLogin().user("jack").password("OldPassword123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("jack"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // Request before password change using the active session passes authentication filter
        // (Returns 404 because /api/documents has no controller mapping, confirming authentication succeeded)
        mockMvc.perform(get("/api/documents").session(session))
                .andExpect(status().isNotFound());

        // Change password, which triggers revocation of all active sessions for 'jack'
        userService.changePassword("jack", "OldPassword123!", "NewPassword123!");

        // Request after password change using the previous session must be intercepted by ConcurrentSessionFilter
        // and redirected to /login?expired because the session was marked expired
        mockMvc.perform(get("/api/documents").session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?expired"));
    }

    @Test
    @DisplayName("Selective session revocation: should preserve specified session while revoking other active sessions")
    void selectiveSessionRevocation_shouldPreserveSpecifiedSession() throws Exception {
        userService.createUser("karen", "Password123!", "karen@example.com", Role.ROLE_USER);

        // First login: Session A (browser 1)
        MvcResult loginA = mockMvc.perform(formLogin().user("karen").password("Password123!"))
                .andExpect(status().isFound())
                .andReturn();
        MockHttpSession sessionA = (MockHttpSession) loginA.getRequest().getSession(false);

        // Second login: Session B (browser 2)
        MvcResult loginB = mockMvc.perform(formLogin().user("karen").password("Password123!"))
                .andExpect(status().isFound())
                .andReturn();
        MockHttpSession sessionB = (MockHttpSession) loginB.getRequest().getSession(false);

        assertThat(sessionA.getId()).isNotEqualTo(sessionB.getId());

        // Both sessions are initially valid
        mockMvc.perform(get("/api/documents").session(sessionA)).andExpect(status().isNotFound());
        mockMvc.perform(get("/api/documents").session(sessionB)).andExpect(status().isNotFound());

        // Selectively revoke other sessions while preserving session A
        userService.revokeOtherUserSessions("karen", sessionA.getId());

        // Session A remains valid
        mockMvc.perform(get("/api/documents").session(sessionA)).andExpect(status().isNotFound());

        // Session B is expired and redirected to /login?expired
        mockMvc.perform(get("/api/documents").session(sessionB))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?expired"));
    }

    @Test
    @DisplayName("Uniqueness violation: exception message must be sanitized without exposing SQL or database details")
    void uniquenessViolation_shouldThrowSanitizedExceptionWithoutRawSql() {
        userService.createUser("leo", "Password123!", "leo@example.com", Role.ROLE_USER);

        assertThatThrownBy(() -> userService.createUser("leo", "DifferentPass123!", "leo.other@example.com", Role.ROLE_USER))
                .isInstanceOf(IllegalArgumentException.class)
                .satisfies(ex -> {
                    String msg = ex.getMessage();
                    assertThat(msg).contains("already in use");
                    // Verify no raw SQL details leak
                    assertThat(msg).doesNotContain("could not execute statement");
                    assertThat(msg).doesNotContain("insert into");
                    assertThat(msg).doesNotContain("app_users");
                    assertThat(msg).doesNotContain("23505");
                });
    }

    @Test
    @DisplayName("CSRF enforcement: POST request without CSRF token must be rejected with 403 Forbidden")
    void csrfProtection_postWithoutToken_shouldReturnForbidden() throws Exception {
        mockMvc.perform(post("/logout"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("CSRF enforcement: POST request with valid CSRF token must be accepted")
    void csrfProtection_postWithValidToken_shouldBeAccepted() throws Exception {
        mockMvc.perform(post("/logout")
                .with(csrf())
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?logout"));
    }

    @Test
    @DisplayName("Health endpoint remains publicly accessible without credentials")
    void healthEndpoint_remainsPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Transaction-safe revocation: rolled-back password change must not revoke active sessions prematurely")
    void passwordChange_whenTransactionRollsBack_shouldNotRevokeActiveSessions() throws Exception {
        userService.createUser("mona", "OldPassword123!", "mona@example.com", Role.ROLE_USER);

        // Authenticate via form login to establish an active session in SessionRegistry
        MvcResult loginResult = mockMvc.perform(formLogin().user("mona").password("OldPassword123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("mona"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // Verify session is active and functional before password change
        mockMvc.perform(get("/api/documents").session(session))
                .andExpect(status().isNotFound());

        // Execute changePassword within a transaction that rolls back
        TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);
        transactionTemplate.execute(status -> {
            userService.changePassword("mona", "OldPassword123!", "NewPassword123!");
            status.setRollbackOnly();
            return null;
        });

        // Database state: password must NOT have been updated due to transaction rollback
        User user = userRepository.findByUsername("mona").orElseThrow();
        assertThat(passwordEncoder.matches("OldPassword123!", user.getPassword())).isTrue();
        assertThat(passwordEncoder.matches("NewPassword123!", user.getPassword())).isFalse();

        // Session state: because transaction rolled back, afterCommit was not called,
        // so the active session must NOT have been revoked and remains valid
        mockMvc.perform(get("/api/documents").session(session))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Transaction-safe revocation: password change without transaction synchronization must still revoke sessions immediately")
    void passwordChange_withoutTransactionSynchronization_shouldRevokeSessionsImmediately() throws Exception {
        userService.createUser("nina", "OldPassword123!", "nina@example.com", Role.ROLE_USER);

        MvcResult loginResult = mockMvc.perform(formLogin().user("nina").password("OldPassword123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("nina"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // Verify session is active before password change
        mockMvc.perform(get("/api/documents").session(session))
                .andExpect(status().isNotFound());

        // Direct call to an unproxied UserService instance where transaction synchronization is inactive
        UserService directService = new UserService(userRepository, passwordEncoder, sessionRegistry);
        assertThat(TransactionSynchronizationManager.isSynchronizationActive()).isFalse();

        directService.changePassword("nina", "OldPassword123!", "NewPassword123!");

        // Session must still be revoked immediately, redirecting to /login?expired
        mockMvc.perform(get("/api/documents").session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?expired"));
    }

    @Test
    @DisplayName("Transaction-safe revocation: duplicate password change calls in same transaction must avoid duplicate synchronizations")
    void multiplePasswordChangesInSameTransaction_shouldAvoidDuplicateRevocationCallbacks() {
        userService.createUser("quinn", "Password123!", "quinn@example.com", Role.ROLE_USER);

        TransactionTemplate transactionTemplate = new TransactionTemplate(transactionManager);
        transactionTemplate.execute(status -> {
            userService.changePassword("quinn", "Password123!", "Password456!");
            userService.changePassword("quinn", "Password456!", "Password789!");

            // Verify that only one synchronization was registered for 'quinn' in this transaction
            long count = TransactionSynchronizationManager.getSynchronizations().stream()
                    .filter(s -> s instanceof UserService.UserSessionRevocationSynchronization userSync
                            && userSync.equals(new UserService.UserSessionRevocationSynchronization("quinn", userService)))
                    .count();
            assertThat(count).isEqualTo(1);
            return null;
        });

        // After successful commit, verify new password is in effect
        User user = userRepository.findByUsername("quinn").orElseThrow();
        assertThat(passwordEncoder.matches("Password789!", user.getPassword())).isTrue();
    }
}
