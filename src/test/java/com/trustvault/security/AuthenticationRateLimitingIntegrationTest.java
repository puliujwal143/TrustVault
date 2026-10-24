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
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationRateLimitingIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthenticationRateLimiter rateLimiter;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        rateLimiter.clearAll();
        userRepository.deleteAll();
        userService.createUser("ratelimit_user", "ValidPassword123!", "ratelimit@example.com", Role.ROLE_USER);
    }

    @Test
    @DisplayName("1. Form login: 5 failed attempts allowed; 6th attempt is blocked and redirected to /login?blocked")
    void testFormLoginThresholdEnforcement() throws Exception {
        String clientIp = "192.168.10.50";

        // First 5 attempts fail authentication normally -> redirected to /login?error
        for (int i = 1; i <= 5; i++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .with(request -> {
                                request.setRemoteAddr(clientIp);
                                return request;
                            })
                            .param("username", "ratelimit_user")
                            .param("password", "WrongPassword!"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/login?error"));
        }

        // 6th attempt is blocked by rate limiting filter BEFORE Spring Security evaluations
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr(clientIp);
                            return request;
                        })
                        .param("username", "ratelimit_user")
                        .param("password", "AnyPassword!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?blocked"))
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    @DisplayName("2. HTTP Basic: 5 failed attempts return 401; 6th attempt is blocked with HTTP 429 Too Many Requests")
    void testHttpBasicThresholdEnforcement() throws Exception {
        String clientIp = "10.0.5.25";
        String invalidHeader = "Basic " + Base64.getEncoder().encodeToString("ratelimit_user:WrongPassword!".getBytes(StandardCharsets.UTF_8));

        // First 5 attempts fail HTTP Basic authentication -> 401 Unauthorized
        for (int i = 1; i <= 5; i++) {
            mockMvc.perform(get("/api/documents")
                            .header(HttpHeaders.AUTHORIZATION, invalidHeader)
                            .with(request -> {
                                request.setRemoteAddr(clientIp);
                                return request;
                            }))
                    .andExpect(status().isUnauthorized());
        }

        // 6th attempt is blocked by rate limiting filter -> HTTP 429 Too Many Requests
        mockMvc.perform(get("/api/documents")
                        .header(HttpHeaders.AUTHORIZATION, invalidHeader)
                        .with(request -> {
                            request.setRemoteAddr(clientIp);
                            return request;
                        }))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.error").value("Too Many Requests"))
                .andExpect(jsonPath("$.message").value(containsString("Too many failed authentication attempts")));
    }

    @Test
    @DisplayName("3. Reset on success: successful login clears failure count and prevents block")
    void testSuccessfulLoginResetsCounter() throws Exception {
        String clientIp = "172.16.0.100";

        // 4 failed attempts (1 away from threshold)
        for (int i = 1; i <= 4; i++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .with(request -> {
                                request.setRemoteAddr(clientIp);
                                return request;
                            })
                            .param("username", "ratelimit_user")
                            .param("password", "WrongPassword!"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/login?error"));
        }

        // 5th attempt: legitimate user provides correct password -> succeeds and redirects to /
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr(clientIp);
                            return request;
                        })
                        .param("username", "ratelimit_user")
                        .param("password", "ValidPassword123!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));

        // Next failure starts fresh at attempt 1 -> redirects to /login?error, NOT blocked!
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr(clientIp);
                            return request;
                        })
                        .param("username", "ratelimit_user")
                        .param("password", "WrongPassword!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    @DisplayName("4. User and IP isolation: attacker locking out user from IP A does not lock out user from IP B")
    void testUserAndIpIsolation() throws Exception {
        String attackerIp = "198.51.100.77";
        String legitimateIp = "203.0.113.88";

        // Attacker triggers rate limit block for ratelimit_user from attackerIp
        for (int i = 1; i <= 5; i++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .with(request -> {
                                request.setRemoteAddr(attackerIp);
                                return request;
                            })
                            .param("username", "ratelimit_user")
                            .param("password", "AttackerGuess!"))
                    .andExpect(status().isFound())
                    .andExpect(redirectedUrl("/login?error"));
        }

        // Attacker is now blocked
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr(attackerIp);
                            return request;
                        })
                        .param("username", "ratelimit_user")
                        .param("password", "AttackerGuess!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?blocked"));

        // Legitimate user on legitimateIp logs in successfully with valid credentials
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr(legitimateIp);
                            return request;
                        })
                        .param("username", "ratelimit_user")
                        .param("password", "ValidPassword123!"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    @DisplayName("5. Health check probe is never throttled for unauthenticated health checks")
    void testHealthCheckProbeNotThrottled() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    @DisplayName("6. Health check probe WITH Basic credentials is intercepted and throttled when blocked")
    void testHealthCheckWithBasicAuthThrottledWhenBlocked() throws Exception {
        String clientIp = "192.168.10.99";
        String invalidHeader = "Basic " + Base64.getEncoder().encodeToString("ratelimit_user:WrongPassword!".getBytes(StandardCharsets.UTF_8));

        // Trigger block with 5 failed Basic auth requests on API endpoint
        for (int i = 1; i <= 5; i++) {
            mockMvc.perform(get("/api/documents")
                            .header(HttpHeaders.AUTHORIZATION, invalidHeader)
                            .with(request -> {
                                request.setRemoteAddr(clientIp);
                                return request;
                            }))
                    .andExpect(status().isUnauthorized());
        }

        // Sending Basic credentials to /api/health must NOT bypass the rate limiter
        mockMvc.perform(get("/api/health")
                        .header(HttpHeaders.AUTHORIZATION, invalidHeader)
                        .with(request -> {
                            request.setRemoteAddr(clientIp);
                            return request;
                        }))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.status").value(429));

        // Pure unauthenticated health probe from same IP is STILL allowed
        mockMvc.perform(get("/api/health")
                        .with(request -> {
                            request.setRemoteAddr(clientIp);
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    @DisplayName("7. Malformed Basic Authorization headers are handled gracefully without 500 errors")
    void testMalformedBasicAuthHeaders() throws Exception {
        // A. Invalid Base64 payload
        mockMvc.perform(get("/api/documents")
                        .header(HttpHeaders.AUTHORIZATION, "Basic !@#$%^&*()_+=-"))
                .andExpect(status().isUnauthorized());

        // B. Decoded payload with no colon (no password separator)
        String noColonHeader = "Basic " + Base64.getEncoder().encodeToString("onlyusername".getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(get("/api/documents")
                        .header(HttpHeaders.AUTHORIZATION, noColonHeader))
                .andExpect(status().isUnauthorized());

        // C. Decoded payload with empty username
        String emptyUserHeader = "Basic " + Base64.getEncoder().encodeToString(":password".getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(get("/api/documents")
                        .header(HttpHeaders.AUTHORIZATION, emptyUserHeader))
                .andExpect(status().isUnauthorized());
    }
}
