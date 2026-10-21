package com.trustvault.repository;

import com.trustvault.entity.Document;
import com.trustvault.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for Document entity persistence.
 *
 * Employs parameterized queries and derived query methods to completely
 * prevent SQL injection vulnerabilities.
 */
@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {

    /**
     * Finds a document by its immutable UUID storage key.
     *
     * @param storageKey the unique UUID storage key
     * @return an Optional containing the Document if found
     */
    Optional<Document> findByStorageKey(UUID storageKey);

    /**
     * Finds all documents owned by a specific User entity.
     *
     * @param owner the User who owns the documents
     * @return list of matching documents
     */
    List<Document> findByOwner(User owner);

    /**
     * Finds all documents owned by a specific username, ordered by most recently updated.
     *
     * @param username the owner's username
     * @return list of matching documents
     */
    List<Document> findByOwnerUsernameOrderByUpdatedAtDesc(String username);

    /**
     * Checks if a document exists and belongs to the specified owner username.
     *
     * @param id       the document ID
     * @param username the expected owner's username
     * @return true if the document exists and is owned by the user
     */
    boolean existsByIdAndOwnerUsername(Long id, String username);

    /**
     * Finds all documents accessible to a given user (either directly owned by the user
     * or explicitly shared with the user through an active DocumentShare grant).
     *
     * @param username the username to query accessible documents for
     * @return list of accessible documents ordered by updated timestamp
     */
    @Query("SELECT d FROM Document d WHERE d.owner.username = :username " +
           "OR d.id IN (SELECT s.document.id FROM DocumentShare s WHERE s.grantee.username = :username) " +
           "ORDER BY d.updatedAt DESC")
    List<Document> findAllAccessibleByUsername(@Param("username") String username);

    /**
     * Counts the total number of documents owned by a user.
     *
     * @param owner the User entity
     * @return count of documents
     */
    long countByOwner(User owner);
}
