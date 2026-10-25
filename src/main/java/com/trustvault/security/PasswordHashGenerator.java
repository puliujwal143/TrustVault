package com.trustvault.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.Console;
import java.util.Scanner;

/**
 * Administrative utility to generate BCrypt-12 hashed passwords offline for secure account provisioning.
 *
 * Security Requirements & Strict Invariants:
 * 1. Prompts for password via System.console().readPassword() to prevent console echoing or shell history capture.
 * 2. Enforces minimum 8 character length matching TrustVault security policy.
 * 3. Uses BCrypt work factor 12 matching PasswordConfig.
 * 4. Never logs, prints, or stores raw passwords.
 */
public class PasswordHashGenerator {

    private static final int WORK_FACTOR = 12;

    public static String hashPassword(String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank() || rawPassword.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }
        return new BCryptPasswordEncoder(WORK_FACTOR).encode(rawPassword);
    }

    public static void main(String[] args) {
        String password;
        if (args.length > 0 && !args[0].isBlank()) {
            password = args[0];
        } else {
            Console console = System.console();
            if (console != null) {
                char[] chars = console.readPassword("Enter password to hash (min 8 chars): ");
                if (chars == null) {
                    System.err.println("Aborted: no input.");
                    return;
                }
                password = new String(chars);
                java.util.Arrays.fill(chars, '\0');
            } else {
                System.out.println("Enter password to hash (min 8 chars): ");
                try (Scanner scanner = new Scanner(System.in)) {
                    if (!scanner.hasNextLine()) {
                        System.err.println("Aborted: no input stream.");
                        return;
                    }
                    password = scanner.nextLine();
                }
            }
        }

        try {
            String hash = hashPassword(password);
            System.out.println("BCrypt (strength 12) Hash:");
            System.out.println(hash);
        } catch (IllegalArgumentException ex) {
            System.err.println("Error: " + ex.getMessage());
        }
    }
}
