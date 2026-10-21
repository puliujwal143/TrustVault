package com.trustvault.dto;

import com.trustvault.entity.Document;
import com.trustvault.entity.Role;
import com.trustvault.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link DocumentResponseDto}.
 *
 * Verifies:
 * - Documents without attached files map to hasFile=false and null file metadata fields.
 * - Documents with attached files map to hasFile=true and populated file metadata fields.
 * - Zero-byte files are correctly represented with hasFile=true and fileSize=0.
 * - Documents with incomplete file metadata map to hasFile=false and null file fields.
 * - Null document input returns null safely.
 * - Documents with null owner return null ownerUsername without exception.
 * - Backward-compatible 7-argument constructor defaults hasFile=false and null file fields.
 * - Sensitive fields (fileStorageKey, fileChecksum, filesystem paths) are NOT exposed in the DTO.
 */
class DocumentResponseDtoTest {

    private static final String VALID_CHECKSUM = "a".repeat(64);

    @Nested
    @DisplayName("1. Metadata-Only Documents (No File Attached)")
    class MetadataOnlyDocumentTests {

        @Test
        @DisplayName("from: metadata-only document maps to hasFile=false and null file metadata fields")
        void testMetadataOnlyDocument() {
            User owner = new User("alice", "encoded_password", "alice@example.com", Role.ROLE_USER);
            Document document = new Document("Q3 Financials", "Quarterly report draft", owner);
            document.setId(101L);
            Instant createdAt = Instant.parse("2026-10-01T10:00:00Z");
            Instant updatedAt = Instant.parse("2026-10-02T15:30:00Z");
            document.setCreatedAt(createdAt);
            document.setUpdatedAt(updatedAt);

            DocumentResponseDto dto = DocumentResponseDto.from(document);

            assertThat(dto).isNotNull();
            assertThat(dto.id()).isEqualTo(101L);
            assertThat(dto.storageKey()).isEqualTo(document.getStorageKey());
            assertThat(dto.title()).isEqualTo("Q3 Financials");
            assertThat(dto.description()).isEqualTo("Quarterly report draft");
            assertThat(dto.ownerUsername()).isEqualTo("alice");
            assertThat(dto.createdAt()).isEqualTo(createdAt);
            assertThat(dto.updatedAt()).isEqualTo(updatedAt);

            // File metadata fields must be null and hasFile must be false
            assertThat(dto.hasFile()).isFalse();
            assertThat(dto.fileOriginalName()).isNull();
            assertThat(dto.fileContentType()).isNull();
            assertThat(dto.fileSize()).isNull();
            assertThat(dto.fileUploadedAt()).isNull();
        }

        @Test
        @DisplayName("from: document with null owner maps ownerUsername to null without throwing NPE")
        void testDocumentWithNullOwner() {
            Document document = new Document("Orphan Doc", "No owner assigned", null);
            document.setId(102L);

            DocumentResponseDto dto = DocumentResponseDto.from(document);

            assertThat(dto).isNotNull();
            assertThat(dto.ownerUsername()).isNull();
            assertThat(dto.hasFile()).isFalse();
        }

        @Test
        @DisplayName("from: null document input returns null safely")
        void testNullDocumentReturnsNull() {
            assertThat(DocumentResponseDto.from(null)).isNull();
        }

        @Test
        @DisplayName("constructor: 7-argument backward-compatible constructor defaults hasFile=false and null file fields")
        void testBackwardCompatibleConstructor() {
            UUID key = UUID.randomUUID();
            Instant now = Instant.now();
            DocumentResponseDto dto = new DocumentResponseDto(
                    201L, key, "Title", "Desc", "bob", now, now
            );

            assertThat(dto.id()).isEqualTo(201L);
            assertThat(dto.storageKey()).isEqualTo(key);
            assertThat(dto.title()).isEqualTo("Title");
            assertThat(dto.description()).isEqualTo("Desc");
            assertThat(dto.ownerUsername()).isEqualTo("bob");
            assertThat(dto.createdAt()).isEqualTo(now);
            assertThat(dto.updatedAt()).isEqualTo(now);
            assertThat(dto.hasFile()).isFalse();
            assertThat(dto.fileOriginalName()).isNull();
            assertThat(dto.fileContentType()).isNull();
            assertThat(dto.fileSize()).isNull();
            assertThat(dto.fileUploadedAt()).isNull();
        }
    }

    @Nested
    @DisplayName("2. Documents With Attached Files")
    class AttachedFileDocumentTests {

        @Test
        @DisplayName("from: document with attached file maps to hasFile=true and populated file metadata")
        void testDocumentWithFile() {
            User owner = new User("charlie", "encoded_password", "charlie@example.com", Role.ROLE_USER);
            Document document = new Document("Audit Report", "Annual security audit", owner);
            document.setId(301L);

            UUID fileKey = UUID.randomUUID();
            Instant uploadTime = Instant.parse("2026-10-15T12:00:00Z");

            document.setFileMetadata(
                    fileKey,
                    "security_audit.pdf",
                    "application/pdf",
                    2_048_576L,
                    VALID_CHECKSUM,
                    uploadTime
            );

            DocumentResponseDto dto = DocumentResponseDto.from(document);

            assertThat(dto).isNotNull();
            assertThat(dto.hasFile()).isTrue();
            assertThat(dto.fileOriginalName()).isEqualTo("security_audit.pdf");
            assertThat(dto.fileContentType()).isEqualTo("application/pdf");
            assertThat(dto.fileSize()).isEqualTo(2_048_576L);
            assertThat(dto.fileUploadedAt()).isEqualTo(uploadTime);

            // Verify that logical storageKey is present but fileStorageKey and checksum are NOT in the record components
            assertThat(dto.storageKey()).isEqualTo(document.getStorageKey());
        }

        @Test
        @DisplayName("from: document with zero-byte file correctly reflects hasFile=true and fileSize=0")
        void testDocumentWithZeroByteFile() {
            User owner = new User("dave", "encoded_password", "dave@example.com", Role.ROLE_USER);
            Document document = new Document("Empty Note", "Placeholder", owner);
            document.setId(302L);

            UUID fileKey = UUID.randomUUID();
            Instant uploadTime = Instant.now();

            document.setFileMetadata(
                    fileKey,
                    "empty.txt",
                    "text/plain",
                    0L,
                    VALID_CHECKSUM,
                    uploadTime
            );

            DocumentResponseDto dto = DocumentResponseDto.from(document);

            assertThat(dto).isNotNull();
            assertThat(dto.hasFile()).isTrue();
            assertThat(dto.fileOriginalName()).isEqualTo("empty.txt");
            assertThat(dto.fileContentType()).isEqualTo("text/plain");
            assertThat(dto.fileSize()).isEqualTo(0L);
            assertThat(dto.fileUploadedAt()).isEqualTo(uploadTime);
        }

        @Test
        @DisplayName("from: document with incomplete file metadata maps to hasFile=false and null file fields")
        void testDocumentWithIncompleteFileMetadata() {
            User owner = new User("eve", "encoded_password", "eve@example.com", Role.ROLE_USER);
            Document document = new Document("Partial Doc", "Corrupted state", owner);
            document.setId(303L);

            // Manually set only some file fields without complete metadata
            document.setFileOriginalName("partial.pdf");
            document.setFileContentType("application/pdf");
            // fileSize, fileChecksum, fileStorageKey, fileUploadedAt remain null

            assertThat(document.hasFile()).isFalse();

            DocumentResponseDto dto = DocumentResponseDto.from(document);

            assertThat(dto).isNotNull();
            assertThat(dto.hasFile()).isFalse();
            assertThat(dto.fileOriginalName()).isNull();
            assertThat(dto.fileContentType()).isNull();
            assertThat(dto.fileSize()).isNull();
            assertThat(dto.fileUploadedAt()).isNull();
        }
    }
}
