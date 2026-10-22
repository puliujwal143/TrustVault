package com.trustvault.security;

import com.trustvault.entity.Role;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for TrustVault Logout workflow:
 * 1. Authenticated user sees the logout form, username, and CSRF token in the navbar.
 * 2. Unauthenticated user does not see the logout form.
 * 3. POST /logout with a valid CSRF token logs out successfully and redirects to /login?logout.
 * 4. The previous session is invalidated and can no longer access protected document pages.
 * 5. Authentication works again after logout.
 * 6. POST /logout without CSRF token is rejected with HTTP 403 Forbidden.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LogoutIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

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

        userService.createUser("alice", "SecurePass123!", "alice@example.com", Role.ROLE_USER);
        userService.createUser("bob", "SecurePass123!", "bob@example.com", Role.ROLE_USER);
    }

    @Test
    @DisplayName("1. Authenticated user sees the logout form, username, and CSRF token in navbar")
    void authenticatedUser_seesLogoutFormAndCsrfToken() throws Exception {
        mockMvc.perform(get("/documents").with(user("alice")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("id=\"navbar-user-profile\"")))
                .andExpect(content().string(containsString("id=\"logout-form\"")))
                .andExpect(content().string(containsString("action=\"/logout\"")))
                .andExpect(content().string(containsString("method=\"post\"")))
                .andExpect(content().string(containsString("id=\"logout-btn\"")))
                .andExpect(content().string(containsString("Logout")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(containsString("alice")));
    }

    @Test
    @DisplayName("2. Unauthenticated user does not see the logout form on public pages")
    void unauthenticatedUser_doesNotSeeLogoutForm() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("id=\"navbar-user-profile\""))))
                .andExpect(content().string(not(containsString("id=\"logout-form\""))))
                .andExpect(content().string(not(containsString("id=\"logout-btn\""))));
    }

    @Test
    @DisplayName("3. POST /logout with a valid CSRF token logs out successfully and redirects to /login?logout")
    void postLogout_withValidCsrf_shouldLogoutSuccessfully() throws Exception {
        // Authenticate alice via form login
        MvcResult loginResult = mockMvc.perform(formLogin().user("alice").password("SecurePass123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("alice"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // Perform POST /logout with CSRF
        mockMvc.perform(post("/logout")
                        .session(session)
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?logout"))
                .andExpect(unauthenticated());
    }

    @Test
    @DisplayName("4. Previous session can no longer access protected document pages after logout")
    void previousSession_cannotAccessProtectedPagesAfterLogout() throws Exception {
        // 1. Authenticate alice
        MvcResult loginResult = mockMvc.perform(formLogin().user("alice").password("SecurePass123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("alice"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // 2. Verify protected page is accessible with active session
        mockMvc.perform(get("/documents").session(session))
                .andExpect(status().isOk());

        // 3. Logout
        mockMvc.perform(post("/logout")
                        .session(session)
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?logout"));

        // 4. Attempt to access protected page with invalidated session -> redirected to /login
        mockMvc.perform(get("/documents").session(session).accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("5. Login works again after logout with different user credentials")
    void loginWorksAgain_afterLogout() throws Exception {
        // 1. Alice logs in
        MvcResult aliceLogin = mockMvc.perform(formLogin().user("alice").password("SecurePass123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("alice"))
                .andReturn();

        MockHttpSession aliceSession = (MockHttpSession) aliceLogin.getRequest().getSession(false);

        // 2. Alice logs out
        mockMvc.perform(post("/logout").session(aliceSession).with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?logout"));

        // 3. Login page renders logout confirmation banner
        mockMvc.perform(get("/login").param("logout", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("id=\"auth-logout-alert\"")))
                .andExpect(content().string(containsString("You have been safely signed out of TrustVault.")));

        // 4. Bob logs in with a fresh session
        MvcResult bobLogin = mockMvc.perform(formLogin().user("bob").password("SecurePass123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("bob"))
                .andReturn();

        MockHttpSession bobSession = (MockHttpSession) bobLogin.getRequest().getSession(false);

        // 5. Bob accesses dashboard and sees Bob's username in navbar
        mockMvc.perform(get("/documents").session(bobSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("id=\"navbar-user-profile\"")))
                .andExpect(content().string(containsString("bob")))
                .andExpect(content().string(containsString("id=\"logout-btn\"")));
    }

    @Test
    @DisplayName("6. POST /logout without CSRF token is rejected with HTTP 403 Forbidden")
    void postLogout_withoutCsrf_shouldBeRejectedWithForbidden() throws Exception {
        MvcResult loginResult = mockMvc.perform(formLogin().user("alice").password("SecurePass123!"))
                .andExpect(status().isFound())
                .andExpect(authenticated().withUsername("alice"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        // Attempt logout without CSRF token
        mockMvc.perform(post("/logout").session(session))
                .andExpect(status().isForbidden());
    }
}
