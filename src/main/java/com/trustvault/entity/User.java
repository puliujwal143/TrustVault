package com.trustvault.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Objects;

/**
 * Persistent user entity for database-backed authentication.
 *
 * Mapped to table 'app_users' to avoid collision with PostgreSQL's reserved
 * SQL keyword 'USER'.
 *
 * JPA Lifecycle Design for equals() and hashCode():
 * - Uses the natural business key ('username') rather than the database-generated 'id'.
 * - In JPA, 'id' is null for transient entities and assigned upon persist. If equals/hashCode
 *   depend on 'id', the entity's hash code mutates after saving, breaking Set and Map contracts
 *   (e.g., set.contains(entity) evaluates to false).
 * - Basing equality on the immutable natural business key guarantees stable identity across all
 *   JPA states: Transient -> Persistent -> Detached -> Removed.
 */
@Entity
@Table(name = "app_users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(min = 3, max = 50)
    @Column(name = "username", nullable = false, unique = true, length = 50, updatable = false)
    private String username;

    /**
     * BCrypt hashed password representation.
     * Plaintext passwords must NEVER be assigned to this field or stored in the database.
     */
    @NotBlank
    @Size(min = 60, max = 100)
    @Column(name = "password", nullable = false, length = 100)
    private String password;

    @NotBlank
    @Email
    @Size(max = 100)
    @Column(name = "email", nullable = false, unique = true, length = 100)
    private String email;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    private Role role;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public User() {
        // Default constructor required by JPA
    }

    public User(String username, String password, String email, Role role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.enabled = true;
    }

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
    }

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * JPA-safe equality based on unique natural key 'username'.
     * Accesses other.getUsername() rather than direct field access to support Hibernate proxies.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User other)) return false;
        return username != null && username.equals(other.getUsername());
    }

    /**
     * Invariant hash code based on unique natural key 'username'.
     * Guarantees the hash code remains unchanged when the entity transitions from
     * transient to persistent state upon database insertion.
     */
    @Override
    public int hashCode() {
        return username != null ? Objects.hash(username) : getClass().hashCode();
    }

    @Override
    public String toString() {
        // Intentionally omits password from string representation to prevent accidental log leakage
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", role=" + role +
                ", enabled=" + enabled +
                ", createdAt=" + createdAt +
                '}';
    }
}
