package com.trustvault.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration for TrustVault.
 *
 * Security Requirements Compliance:
 * - Spring Security is NOT disabled globally.
 * - All application routes require authentication by default.
 * - Only the health check probe (/api/health) is explicitly whitelisted for unauthenticated access.
 * - Uploaded documents are NOT exposed via public static directories.
 * - Fine-grained, document-level authorization will be implemented in subsequent phases.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                // Publicly accessible health check probe
                .requestMatchers("/api/health").permitAll()
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults())
            .formLogin(Customizer.withDefaults());

        return http.build();
    }
}
