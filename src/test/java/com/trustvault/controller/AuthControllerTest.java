package com.trustvault.controller;

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
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Integration tests for AuthController, custom login view rendering,
 * static asset access, and appearance theme fragments.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("GET /login: unauthenticated request renders the custom login view with HTTP 200 OK")
    void testLoginPageRendersSuccessfully() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(containsString("Sign in to TrustVault")))
                .andExpect(content().string(containsString("name=\"username\"")))
                .andExpect(content().string(containsString("name=\"password\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(containsString("trustvault_theme_pref")))
                .andExpect(content().string(containsString("data-theme-value=\"light\"")))
                .andExpect(content().string(containsString("data-theme-value=\"dark\"")))
                .andExpect(content().string(containsString("data-theme-value=\"system\"")))
                .andExpect(content().string(containsString("Public registration is disabled")));
    }

    @Test
    @DisplayName("GET /login?error: renders invalid credentials alert banner")
    void testLoginPageShowsErrorBanner() throws Exception {
        mockMvc.perform(get("/login").param("error", ""))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("Authentication Failed")))
                .andExpect(content().string(containsString("Invalid username or password")));
    }

    @Test
    @DisplayName("GET /login?expired: renders session expired alert banner")
    void testLoginPageShowsExpiredBanner() throws Exception {
        mockMvc.perform(get("/login").param("expired", ""))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("Session Expired")))
                .andExpect(content().string(containsString("Your session has expired")));
    }

    @Test
    @DisplayName("GET /login?logout: renders safe sign-out alert banner")
    void testLoginPageShowsLogoutBanner() throws Exception {
        mockMvc.perform(get("/login").param("logout", ""))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("Signed Out")))
                .andExpect(content().string(containsString("You have been safely signed out")));
    }

    @Test
    @DisplayName("GET /css/theme.css: static theme stylesheet is publicly accessible with HTTP 200")
    void testThemeStylesheetPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/css/theme.css"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/css"))
                .andExpect(content().string(containsString("--color-accent: #059669")))
                .andExpect(content().string(containsString("[data-theme=\"dark\"]")));
    }

    @Test
    @DisplayName("GET /css/layout.css: static layout stylesheet is publicly accessible with HTTP 200")
    void testLayoutStylesheetPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/css/layout.css"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/css"))
                .andExpect(content().string(containsString(".app-navbar")))
                .andExpect(content().string(containsString(".app-sidebar")));
    }

    @Test
    @DisplayName("GET /css/components.css: static component stylesheet is publicly accessible with HTTP 200")
    void testComponentStylesheetPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/css/components.css"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/css"))
                .andExpect(content().string(containsString(".theme-selector")))
                .andExpect(content().string(containsString(".alert-danger")));
    }

    @Test
    @DisplayName("GET /js/theme.js: static theme JavaScript is publicly accessible with HTTP 200")
    void testThemeScriptPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/js/theme.js"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("trustvault_theme_pref")))
                .andExpect(content().string(containsString("prefers-color-scheme: dark")));
    }

    @Test
    @DisplayName("GET /images/logo.svg: static logo image is publicly accessible with HTTP 200")
    void testLogoImagePubliclyAccessible() throws Exception {
        mockMvc.perform(get("/images/logo.svg"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("image/svg+xml"));
    }

    @Test
    @DisplayName("Form login: valid credentials authenticates successfully and redirects to default URL")
    void testFormLoginSuccess() throws Exception {
        userService.createUser("validuser", "Password123!", "user@example.com", Role.ROLE_USER);

        mockMvc.perform(formLogin("/login").user("validuser").password("Password123!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername("validuser"));
    }

    @Test
    @DisplayName("Form login: invalid credentials fails authentication and redirects to /login?error")
    void testFormLoginFailure() throws Exception {
        userService.createUser("user2", "Password123!", "user2@example.com", Role.ROLE_USER);

        mockMvc.perform(formLogin("/login").user("user2").password("WrongPassword999!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());
    }
}
