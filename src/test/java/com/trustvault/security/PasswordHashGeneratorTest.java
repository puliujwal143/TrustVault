package com.trustvault.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordHashGeneratorTest {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    @Test
    @DisplayName("hashPassword generates valid BCrypt work-factor 12 hash")
    void validPasswordGeneratesBCryptHash() {
        String rawPassword = "ValidTestPassword123!";
        String hash = PasswordHashGenerator.hashPassword(rawPassword);

        assertThat(hash).isNotNull().startsWith("$2a$12$");
        assertThat(encoder.matches(rawPassword, hash)).isTrue();
        assertThat(encoder.matches("WrongPassword123!", hash)).isFalse();
    }

    @Test
    @DisplayName("hashPassword rejects blank or short passwords")
    void rejectsShortOrBlankPassword() {
        assertThatThrownBy(() -> PasswordHashGenerator.hashPassword(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 8 characters");

        assertThatThrownBy(() -> PasswordHashGenerator.hashPassword("short"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 8 characters");

        assertThatThrownBy(() -> PasswordHashGenerator.hashPassword(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 8 characters");
    }

    @Test
    @DisplayName("main method executes successfully with command line argument")
    void mainWithArgumentGeneratesHash() {
        java.io.ByteArrayOutputStream outContent = new java.io.ByteArrayOutputStream();
        java.io.PrintStream originalOut = System.out;
        try {
            System.setOut(new java.io.PrintStream(outContent));
            PasswordHashGenerator.main(new String[]{"CliTestPassword123!"});
            String output = outContent.toString();
            assertThat(output).contains("BCrypt (strength 12) Hash:");
            assertThat(output).contains("$2a$12$");
        } finally {
            System.setOut(originalOut);
        }
    }

    @Test
    @DisplayName("main method executes successfully with standard input stream")
    void mainWithInputStreamGeneratesHash() {
        java.io.InputStream originalIn = System.in;
        java.io.ByteArrayOutputStream outContent = new java.io.ByteArrayOutputStream();
        java.io.PrintStream originalOut = System.out;
        try {
            System.setIn(new java.io.ByteArrayInputStream("StreamTestPassword123!\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            System.setOut(new java.io.PrintStream(outContent));
            PasswordHashGenerator.main(new String[0]);
            String output = outContent.toString();
            assertThat(output).contains("Enter password to hash");
            assertThat(output).contains("BCrypt (strength 12) Hash:");
            assertThat(output).contains("$2a$12$");
        } finally {
            System.setIn(originalIn);
            System.setOut(originalOut);
        }
    }

    @Test
    @DisplayName("main method rejects short password entered via standard input")
    void mainWithShortInputStreamPrintsError() {
        java.io.InputStream originalIn = System.in;
        java.io.ByteArrayOutputStream errContent = new java.io.ByteArrayOutputStream();
        java.io.PrintStream originalErr = System.err;
        try {
            System.setIn(new java.io.ByteArrayInputStream("short\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            System.setErr(new java.io.PrintStream(errContent));
            PasswordHashGenerator.main(new String[0]);
            String errOutput = errContent.toString();
            assertThat(errOutput).contains("Error: Password must be at least 8 characters");
        } finally {
            System.setIn(originalIn);
            System.setErr(originalErr);
        }
    }
}
