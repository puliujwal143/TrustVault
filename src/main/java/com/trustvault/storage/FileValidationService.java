package com.trustvault.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

/**
 * Service enforcing strict file upload validation policies for TrustVault.
 *
 * <p>Security & Verification Architecture:
 * <ul>
 *   <li><b>Strict Size Bounds</b>: Enforces a maximum payload size of exactly 10 MiB (10,485,760 bytes)
 *       both via declared size metadata and proactive streaming byte-counting. Rejects empty (0-byte) files.</li>
 *   <li><b>Zero Path Trust & Filename Sanitization</b>: Original filenames are never used to construct
 *       server filesystem paths. Basenames are extracted, bounded to 255 characters, and stripped of
 *       illegal control characters, NUL bytes, and directory traversal sequences.</li>
 *   <li><b>Allowlist & Signature Verification</b>:
 *     <ul>
 *       <li>PDF: Verifies header {@code %PDF-} (offset 0).</li>
 *       <li>PNG: Verifies 8-byte PNG header {@code 89 50 4E 47 0D 0A 1A 0A}.</li>
 *       <li>JPEG: Verifies 3-byte SOI marker {@code FF D8 FF}.</li>
 *       <li>TXT & CSV: Enforces valid UTF-8 encoding and strictly rejects binary content containing NUL bytes.</li>
 *       <li>Office Open XML (DOCX, XLSX, PPTX): Inspects ZIP container structures in-memory without disk extraction,
 *           requiring {@code [Content_Types].xml} and format-specific root document entries ({@code word/document.xml},
 *           {@code xl/workbook.xml}, or {@code ppt/presentation.xml}). Defends against Zip-Slip and Zip-Bombs by
 *           enforcing bounded entry counts and decompressed byte limits.</li>
 *     </ul>
 *   </li>
 *   <li><b>Cryptographic Integrity</b>: Computes the 64-character lowercase hexadecimal SHA-256 digest
 *       over the validated payload.</li>
 * </ul>
 *
 * <p><b>Security Disclaimer</b>: Signature and container validation establishes structural conformance
 * and format compliance, mitigating obvious extension spoofing and file format confusion attacks.
 * It does not provide anti-virus scanning, heuristic behavioral analysis, or immunity against
 * embedded active content, zero-day vulnerabilities, or malicious macro payloads. Downstream
 * components must apply defense-in-depth (e.g. non-executable storage, safe download headers).
 */
@Service
public class FileValidationService {

    private static final Logger log = LoggerFactory.getLogger(FileValidationService.class);

    public static final long MAX_FILE_SIZE_BYTES = 10L * 1024L * 1024L; // 10 MiB = 10,485,760 bytes
    public static final int MAX_FILENAME_LENGTH = 255;
    public static final int MAX_ARCHIVE_ENTRIES = 1000;
    public static final long MAX_ARCHIVE_DECOMPRESSED_BYTES = 50L * 1024L * 1024L;

    // Magic Byte Signatures
    private static final byte[] PDF_MAGIC = new byte[]{0x25, 0x50, 0x44, 0x46, 0x2D}; // %PDF-
    private static final byte[] PNG_MAGIC = new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    private static final byte[] JPEG_MAGIC = new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};
    private static final byte[] ZIP_MAGIC = new byte[]{0x50, 0x4B, 0x03, 0x04}; // PK\x03\x04

    // Canonical Content Types
    public static final String MIME_PDF = "application/pdf";
    public static final String MIME_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    public static final String MIME_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    public static final String MIME_PPTX = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    public static final String MIME_TXT = "text/plain";
    public static final String MIME_CSV = "text/csv";
    public static final String MIME_PNG = "image/png";
    public static final String MIME_JPEG = "image/jpeg";

    // Supported Extension to Canonical MIME Mapping
    private static final Map<String, String> EXTENSION_TO_CANONICAL_MIME = Map.of(
            ".pdf", MIME_PDF,
            ".docx", MIME_DOCX,
            ".xlsx", MIME_XLSX,
            ".pptx", MIME_PPTX,
            ".txt", MIME_TXT,
            ".csv", MIME_CSV,
            ".png", MIME_PNG,
            ".jpg", MIME_JPEG,
            ".jpeg", MIME_JPEG
    );

    // Permitted Declared MIME Types per Extension (Permissive Aliases for Client Compatibility)
    private static final Map<String, Set<String>> PERMITTED_DECLARED_MIMES = Map.of(
            ".pdf", Set.of(MIME_PDF, "application/x-pdf", "application/acrobat", "applications/vnd.pdf", "text/pdf"),
            ".docx", Set.of(MIME_DOCX, "application/zip", "application/x-zip-compressed", "application/octet-stream"),
            ".xlsx", Set.of(MIME_XLSX, "application/zip", "application/x-zip-compressed", "application/octet-stream"),
            ".pptx", Set.of(MIME_PPTX, "application/zip", "application/x-zip-compressed", "application/octet-stream"),
            ".txt", Set.of(MIME_TXT, "text/*"),
            ".csv", Set.of(MIME_CSV, MIME_TXT, "application/csv", "application/vnd.ms-excel", "text/comma-separated-values"),
            ".png", Set.of(MIME_PNG),
            ".jpg", Set.of(MIME_JPEG, "image/jpg", "image/pjpeg"),
            ".jpeg", Set.of(MIME_JPEG, "image/jpg", "image/pjpeg")
    );

    /**
     * Validates an uploaded Spring {@link MultipartFile} against all security rules.
     *
     * @param file the multipart file payload
     * @return validated file metadata including normalized attributes and buffered content
     * @throws FileValidationException if validation fails
     */
    public ValidatedFileMetadata validate(MultipartFile file) {
        if (file == null) {
            throw new FileValidationException("Upload file payload must not be null");
        }
        try {
            return validate(file.getInputStream(), file.getOriginalFilename(), file.getContentType(), file.getSize());
        } catch (IOException e) {
            throw new FileValidationException("Failed to read upload stream: " + e.getMessage(), e);
        }
    }

    /**
     * Validates an in-memory byte array against all security rules.
     *
     * @param content             the file bytes
     * @param originalFilename    client-supplied filename
     * @param declaredContentType client-supplied MIME content type
     * @return validated file metadata
     * @throws FileValidationException if validation fails
     */
    public ValidatedFileMetadata validate(byte[] content, String originalFilename, String declaredContentType) {
        if (content == null) {
            throw new FileValidationException("File content must not be null");
        }
        return validate(new ByteArrayInputStream(content), originalFilename, declaredContentType, (long) content.length);
    }

    /**
     * Core streaming validation entry point. Reads and bounds input stream, sanitizes filename,
     * cross-checks declared metadata against actual content signatures, and calculates SHA-256.
     *
     * @param inputStream         incoming file data stream (required)
     * @param originalFilename    client-provided filename (required)
     * @param declaredContentType client-declared MIME type (optional, checked if present)
     * @param declaredSize        client-declared size in bytes (optional, checked if present)
     * @return validated file metadata ready for entity association
     * @throws FileValidationException if any security check fails
     */
    public ValidatedFileMetadata validate(InputStream inputStream, String originalFilename, String declaredContentType, Long declaredSize) {
        if (inputStream == null) {
            throw new FileValidationException("Input stream must not be null");
        }

        // 1. Proactive declared size pre-check
        if (declaredSize != null) {
            if (declaredSize == 0) {
                throw new FileValidationException("File must not be empty");
            }
            if (declaredSize < 0) {
                throw new FileValidationException("File size must not be negative: " + declaredSize);
            }
            if (declaredSize > MAX_FILE_SIZE_BYTES) {
                throw new FileValidationException(
                        String.format(Locale.ROOT, "File size (%d bytes) exceeds maximum permitted limit of 10 MiB (%d bytes)",
                                declaredSize, MAX_FILE_SIZE_BYTES));
            }
        }

        // 2. Filename validation and extension extraction
        String sanitizedFilename = validateAndSanitizeFilename(originalFilename);
        String extension = extractExtension(sanitizedFilename);

        String canonicalMime = EXTENSION_TO_CANONICAL_MIME.get(extension);
        if (canonicalMime == null) {
            throw new FileValidationException("Unsupported file extension: '" + extension + "'. Allowed formats: PDF, DOCX, XLSX, PPTX, TXT, CSV, PNG, JPG, JPEG");
        }

        // 3. Declared MIME cross-check (if declared by caller)
        validateDeclaredContentType(extension, declaredContentType);

        // 4. Stream reading with bounded counting and SHA-256 calculation
        byte[] payloadBytes = readStreamWithBound(inputStream);

        // 5. Empty payload and declared size verification
        if (payloadBytes.length == 0) {
            throw new FileValidationException("File must not be empty");
        }
        if (declaredSize != null && declaredSize != (long) payloadBytes.length) {
            throw new FileValidationException(String.format(
                    Locale.ROOT,
                    "Actual file size (%d bytes) does not match declared size (%d bytes)",
                    payloadBytes.length, declaredSize
            ));
        }

        // 6. Deep content & signature verification
        verifyContentSignature(extension, payloadBytes);

        // 7. Calculate SHA-256 checksum
        String checksum = calculateSha256(payloadBytes);

        log.debug("Successfully validated upload file: name='{}', mime='{}', size={} bytes, sha256={}",
                sanitizedFilename, canonicalMime, payloadBytes.length, checksum);

        return new ValidatedFileMetadata(
                sanitizedFilename,
                canonicalMime,
                payloadBytes.length,
                checksum,
                payloadBytes
        );
    }

    /**
     * Sanitizes and bounds client-supplied filenames.
     * Extracts basename, disallows control characters, null bytes, and traversal attempts.
     */
    private String validateAndSanitizeFilename(String rawFilename) {
        if (rawFilename == null || rawFilename.isBlank()) {
            throw new FileValidationException("Filename must not be null or blank");
        }

        if (rawFilename.contains("..")) {
            throw new FileValidationException("Filename contains illegal path traversal sequence: '..'");
        }

        // Strip any client-supplied directory path components (Unix or Windows)
        int lastUnix = rawFilename.lastIndexOf('/');
        int lastWin = rawFilename.lastIndexOf('\\');
        int lastSep = Math.max(lastUnix, lastWin);
        String baseName = lastSep >= 0 ? rawFilename.substring(lastSep + 1) : rawFilename;

        String trimmed = baseName.trim();
        if (trimmed.isEmpty()) {
            throw new FileValidationException("Filename must not be empty after path stripping");
        }

        if (trimmed.length() > MAX_FILENAME_LENGTH) {
            throw new FileValidationException("Filename exceeds maximum permitted length of " + MAX_FILENAME_LENGTH + " characters: " + trimmed.length());
        }

        // Defend against null bytes and control characters (ASCII 0-31 and 127)
        if (trimmed.indexOf('\0') >= 0) {
            throw new FileValidationException("Filename contains illegal NUL character");
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c < 32 || c == 127) {
                throw new FileValidationException("Filename contains illegal control character at index " + i);
            }
        }

        return trimmed;
    }

    /**
     * Extracts lowercase file extension from sanitized filename.
     */
    private String extractExtension(String filename) {
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex <= 0 || dotIndex == filename.length() - 1) {
            throw new FileValidationException("Filename must possess a valid file extension: " + filename);
        }
        return filename.substring(dotIndex).toLowerCase(Locale.ROOT);
    }

    /**
     * Cross-checks client-declared Content-Type against allowed MIME aliases for the extension.
     */
    private void validateDeclaredContentType(String extension, String declaredContentType) {
        if (declaredContentType == null || declaredContentType.isBlank()) {
            return; // Declared Content-Type is optional; content signature will govern
        }

        // Strip optional parameters (e.g. "text/plain; charset=UTF-8" -> "text/plain")
        String normalizedDeclared = declaredContentType.split(";")[0].trim().toLowerCase(Locale.ROOT);

        Set<String> permitted = PERMITTED_DECLARED_MIMES.get(extension);
        if (permitted == null || !permitted.contains(normalizedDeclared)) {
            throw new FileValidationException(String.format(
                    Locale.ROOT,
                    "Declared Content-Type '%s' does not match permitted types for extension '%s'",
                    declaredContentType, extension
            ));
        }
    }

    /**
     * Reads incoming stream into a byte array, enforcing the 10 MiB bound during streaming.
     */
    private byte[] readStreamWithBound(InputStream inputStream) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long totalBytesRead = 0;
        int bytesRead;

        try {
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                totalBytesRead += bytesRead;
                if (totalBytesRead > MAX_FILE_SIZE_BYTES) {
                    throw new FileValidationException(String.format(
                            Locale.ROOT,
                            "File stream exceeded maximum permitted limit of 10 MiB (%d bytes)",
                            MAX_FILE_SIZE_BYTES
                    ));
                }
                baos.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new FileValidationException("I/O error reading upload file stream: " + e.getMessage(), e);
        }

        return baos.toByteArray();
    }

    /**
     * Dispatches content verification based on file extension.
     */
    private void verifyContentSignature(String extension, byte[] content) {
        switch (extension) {
            case ".pdf" -> verifyPdfSignature(content);
            case ".png" -> verifyPngSignature(content);
            case ".jpg", ".jpeg" -> verifyJpegSignature(content);
            case ".txt" -> verifyPlainText(content, "TXT");
            case ".csv" -> verifyPlainText(content, "CSV");
            case ".docx" -> verifyOfficeOpenXml(content, "DOCX", "word/document.xml");
            case ".xlsx" -> verifyOfficeOpenXml(content, "XLSX", "xl/workbook.xml");
            case ".pptx" -> verifyOfficeOpenXml(content, "PPTX", "ppt/presentation.xml");
            default -> throw new FileValidationException("Unsupported file type: " + extension);
        }
    }

    private void verifyPdfSignature(byte[] content) {
        if (!startsWith(content, PDF_MAGIC)) {
            throw new FileValidationException("File content does not match PDF signature ('%PDF-')");
        }
    }

    private void verifyPngSignature(byte[] content) {
        if (!startsWith(content, PNG_MAGIC)) {
            throw new FileValidationException("File content does not match PNG signature");
        }
    }

    private void verifyJpegSignature(byte[] content) {
        if (!startsWith(content, JPEG_MAGIC)) {
            throw new FileValidationException("File content does not match JPEG signature");
        }
    }

    /**
     * Validates that plaintext files (TXT, CSV) contain valid UTF-8 and zero binary NUL bytes.
     */
    private void verifyPlainText(byte[] content, String formatName) {
        // 1. Check for NUL bytes (indicator of binary executables, shellcode, or corrupted binary files)
        for (int i = 0; i < content.length; i++) {
            if (content[i] == 0) {
                throw new FileValidationException(formatName + " file contains forbidden binary NUL byte at offset " + i);
            }
        }

        // 2. Validate strict UTF-8 character encoding
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);

        try {
            decoder.decode(ByteBuffer.wrap(content));
        } catch (CharacterCodingException e) {
            throw new FileValidationException(formatName + " file is not valid UTF-8 text: " + e.getMessage());
        }
    }

    /**
     * Verifies Office Open XML (OOXML) documents in-memory:
     * 1. Must start with ZIP header PK\x03\x04.
     * 2. Must contain [Content_Types].xml.
     * 3. Must contain the format-specific document entry (e.g. word/document.xml).
     * 4. Enforces entry count and decompressed size limits against Zip-Bombs.
     * 5. Defends against Zip-Slip path traversal inside entry names.
     */
    private void verifyOfficeOpenXml(byte[] content, String formatName, String requiredEntryExact) {
        if (!startsWith(content, ZIP_MAGIC)) {
            throw new FileValidationException(formatName + " document does not have a valid ZIP/OOXML container header");
        }

        boolean foundContentTypes = false;
        boolean foundDocumentEntry = false;
        int entryCount = 0;
        long totalDecompressedBytes = 0;

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
            ZipEntry entry;
            byte[] discardBuffer = new byte[4096];

            while ((entry = zis.getNextEntry()) != null) {
                entryCount++;
                if (entryCount > MAX_ARCHIVE_ENTRIES) {
                    throw new FileValidationException(String.format(
                            Locale.ROOT,
                            "%s archive exceeds maximum permitted entry count (%d)",
                            formatName, MAX_ARCHIVE_ENTRIES
                    ));
                }

                String entryName = entry.getName();

                // Zip-Slip defense: reject directory traversal or absolute paths inside archive
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    throw new FileValidationException(String.format(
                            Locale.ROOT,
                            "%s archive contains illegal entry path traversal: '%s'",
                            formatName, entryName
                    ));
                }

                String normalizedName = entryName.toLowerCase(Locale.ROOT);
                if (normalizedName.equals("[content_types].xml")) {
                    foundContentTypes = true;
                }
                if (normalizedName.equals(requiredEntryExact.toLowerCase(Locale.ROOT))) {
                    foundDocumentEntry = true;
                }

                // Guard against Zip-Bombs: inspect entries with bounded byte consumption
                int bytesRead;
                while ((bytesRead = zis.read(discardBuffer)) != -1) {
                    totalDecompressedBytes += bytesRead;
                    if (totalDecompressedBytes > MAX_ARCHIVE_DECOMPRESSED_BYTES) {
                        throw new FileValidationException(String.format(
                                Locale.ROOT,
                                "%s archive exceeded maximum permitted decompressed size of %d bytes",
                                formatName, MAX_ARCHIVE_DECOMPRESSED_BYTES
                        ));
                    }
                }
                zis.closeEntry();
            }
        } catch (ZipException e) {
            throw new FileValidationException(formatName + " archive is malformed or corrupted: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new FileValidationException("I/O error inspecting " + formatName + " archive: " + e.getMessage(), e);
        }

        if (!foundContentTypes) {
            throw new FileValidationException(formatName + " archive is missing required '[Content_Types].xml' entry");
        }

        if (!foundDocumentEntry) {
            throw new FileValidationException(String.format(
                    Locale.ROOT,
                    "%s archive is missing required document entry '%s'",
                    formatName, requiredEntryExact
            ));
        }
    }

    private boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Calculates the SHA-256 digest formatted as 64 lowercase hexadecimal characters.
     */
    public String calculateSha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm must be available in standard JVM", e);
        }
    }

    /**
     * Calculates the SHA-256 digest of an input stream formatted as 64 lowercase hexadecimal characters.
     * Enforces bounded byte consumption up to MAX_FILE_SIZE_BYTES to prevent memory/resource exhaustion.
     *
     * @param inputStream data stream to hash
     * @return 64-character lowercase hexadecimal SHA-256 digest
     * @throws IOException if stream reading fails
     * @throws FileValidationException if the payload exceeds MAX_FILE_SIZE_BYTES
     */
    public String calculateSha256(InputStream inputStream) throws IOException {
        Objects.requireNonNull(inputStream, "InputStream must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            long bytesReadTotal = 0;
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                bytesReadTotal += bytesRead;
                if (bytesReadTotal > MAX_FILE_SIZE_BYTES) {
                    throw new FileValidationException(String.format(
                            Locale.ROOT,
                            "File payload exceeds maximum permitted size limit of %d bytes",
                            MAX_FILE_SIZE_BYTES
                    ));
                }
                digest.update(buffer, 0, bytesRead);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm must be available in standard JVM", e);
        }
    }
}
