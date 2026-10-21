package com.trustvault.repository;

import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for DocumentShare entity persistence.
 *
 * Employs parameterized queries and derived query methods to completely
 * prevent SQL injection vulnerabilities.
 */
@Repository
public interface DocumentShareRepository extends JpaRepository<DocumentShare, Long> {

    /**
     * Finds an active share grant for a specific document and grantee username.
     *
     * @param documentId      the ID of the document
     * @param granteeUsername the username of the grantee
     * @return an Optional containing the DocumentShare if present
     */
    Optional<DocumentShare> findByDocumentIdAndGranteeUsername(Long documentId, String granteeUsername);

    /**
     * Finds an active share grant for a specific Document and User entity.
     *
     * @param document the Document entity
     * @param grantee  the grantee User entity
     * @return an Optional containing the DocumentShare if present
     */
    Optional<DocumentShare> findByDocumentAndGrantee(Document document, User grantee);

    /**
     * Finds all active share grants for a given document ID.
     *
     * @param documentId the ID of the document
     * @return list of share grants for the document
     */
    List<DocumentShare> findByDocumentId(Long documentId);

    /**
     * Finds all active share grants for a given Document entity.
     *
     * @param document the Document entity
     * @return list of share grants for the document
     */
    List<DocumentShare> findByDocument(Document document);

    /**
     * Finds all documents shared with a specific grantee username.
     *
     * @param granteeUsername the grantee's username
     * @return list of share grants assigned to this user
     */
    List<DocumentShare> findByGranteeUsername(String granteeUsername);

    /**
     * Checks if a share grant exists for the specified document ID and grantee username.
     *
     * @param documentId      the ID of the document
     * @param granteeUsername the username of the grantee
     * @return true if a share record exists
     */
    boolean existsByDocumentIdAndGranteeUsername(Long documentId, String granteeUsername);

    /**
     * Deletes an active share grant for a specific document ID and grantee username.
     *
     * @param documentId      the ID of the document
     * @param granteeUsername the username of the grantee
     */
    void deleteByDocumentIdAndGranteeUsername(Long documentId, String granteeUsername);

    /**
     * Deletes all shares associated with a document ID.
     *
     * @param documentId the ID of the document
     */
    void deleteByDocumentId(Long documentId);
}
