package com.trustvault.repository;

import com.trustvault.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA repository for User entity operations.
 *
 * Employs parameterized queries and method name derivation to guarantee
 * protection against SQL injection vulnerabilities.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Looks up a user account by exact username match.
     *
     * @param username the username to query
     * @return an Optional containing the User if present
     */
    Optional<User> findByUsername(String username);

    /**
     * Looks up a user account by exact email address match.
     *
     * @param email the email to query
     * @return an Optional containing the User if present
     */
    Optional<User> findByEmail(String email);

    /**
     * Checks if a user already exists with the given username.
     *
     * @param username the username to check
     * @return true if a record exists
     */
    boolean existsByUsername(String username);

    /**
     * Checks if a user already exists with the given email address.
     *
     * @param email the email to check
     * @return true if a record exists
     */
    boolean existsByEmail(String email);
}
