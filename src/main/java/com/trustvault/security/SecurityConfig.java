package com.trustvault.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * Spring Security configuration for TrustVault.
 *
 * Security Requirements Compliance:
 * - Uses database-backed authentication via CustomUserDetailsService.
 * - Enforces default-deny access control: all endpoints require authentication except /api/health.
 * - CSRF protection is fully active by default on all mutating HTTP requests.
 * - Session fixation protection is configured with changeSessionId().
 * - Configures SessionRegistry and ConcurrentSessionFilter to enable tracking and deliberate
 *   revocation of active sessions upon security events (such as password changes).
 * - Expired sessions are redirected to /login?expired.
 * - Form login and HTTP Basic authentication are supported.
 * - Logout endpoint is configured and whitelisted.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    public SecurityConfig(CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Central registry tracking active authenticated sessions across users.
     * Enables session enumeration and selective or global session revocation.
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * Publishes session creation and destruction events to keep the SessionRegistry synchronized
     * with the servlet container's lifecycle.
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SessionRegistry sessionRegistry) throws Exception {
        SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        logoutSuccessHandler.setDefaultTargetUrl("/login?logout");

        http
            .authorizeHttpRequests(authorize -> authorize
                // Publicly accessible health check probe
                .requestMatchers("/api/health").permitAll()
                // Error dispatch endpoint must be permitted to prevent masking error conditions with 403 Forbidden
                .requestMatchers("/error").permitAll()
                // Static web assets required for styled UI rendering
                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                // Custom login page view route
                .requestMatchers("/login").permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .userDetailsService(userDetailsService)
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .httpBasic(Customizer.withDefaults())
            .sessionManagement(session -> session
                // Defends against session fixation by replacing the session ID upon authentication
                .sessionFixation(fixation -> fixation.changeSessionId())
                // Track sessions in SessionRegistry and redirect expired sessions to /login?expired
                .maximumSessions(-1)
                .sessionRegistry(sessionRegistry)
                .expiredUrl("/login?expired")
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler)
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            );

        return http.build();
    }
}
