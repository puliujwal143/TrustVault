package com.trustvault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * TrustVault Application Entry Point.
 *
 * TrustVault is an enterprise-grade secure document-sharing platform.
 * Phase 1 establishes the architectural foundation, security baseline,
 * and essential configuration.
 */
@SpringBootApplication
public class TrustVaultApplication {

    public static void main(String[] args) {
        SpringApplication.run(TrustVaultApplication.class, args);
    }
}
