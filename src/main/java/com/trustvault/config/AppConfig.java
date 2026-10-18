package com.trustvault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * General application configuration for TrustVault.
 *
 * Configures application-wide infrastructure beans such as Clock,
 * which enables deterministic time testing and consistent audit timestamps.
 */
@Configuration
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
