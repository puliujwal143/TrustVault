package com.trustvault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password encoder configuration.
 *
 * Isolated in a dedicated configuration class to avoid circular dependency
 * cycles between SecurityConfig and UserDetailsService / UserService.
 */
@Configuration
public class PasswordConfig {

    /**
     * BCrypt password encoder with a work factor (strength) of 12.
     *
     * A work factor of 12 represents 2^12 (4,096) hashing iterations, providing
     * strong protection against offline brute-force attacks while maintaining
     * sub-second login verification latency for legitimate users.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
