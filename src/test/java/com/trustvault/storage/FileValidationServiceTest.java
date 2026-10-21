package com.trustvault.storage;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Comprehensive unit tests for {@link FileValidationService}.
 *
 * Covers:
 * - Valid synthetic examples of all supported formats (PDF, DOCX, XLSX, PPTX, TXT, CSV, PNG, JPG, JPEG).
 * - Empty, negative, and oversized files (declared metadata and streaming limits).
 * - Extension, declared MIME, and signature cross-checking.
 * - UTF-8 compliance and binary NUL byte rejection for plaintext files.
 * - OOXML ZIP container inspection, Zip-Slip rejection, and missing entry checks.
 * - Arbitrary ZIP archives renamed to Office extensions.
 * - Filename sanitization, path normalization, control character rejection, and length bounds.
 * - Stream limits and malformed input handling.
 */
class FileValidationServiceTest {

    private final FileValidationService validationService = new FileValidationService();

    // Synthetic File Fixtures
    private static final byte[] VALID_PDF_BYTES = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VALID_PNG_BYTES = new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // 8-byte PNG magic
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52          // IHDR chunk header
    };
    private static final byte[] VALID_JPEG_BYTES = new byte[]{
            (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0,     // SOI + APP0 marker
            0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00               // 'JFIF' identifier
    };
    private static final byte[] VALID_TXT_BYTES = "Hello TrustVault!\nSafe UTF-8 plain text: äöü, € and 日本語".getBytes(StandardCharsets.UTF_8);
    private static final byte[] VALID_CSV_BYTES = "id,name,role\n1,Alice,Admin\n2,Bob,Editor\n".getBytes(StandardCharsets.UTF_8);

    @Nested
    @DisplayName("1. Valid Formats")
    class ValidFormatTests {

        @Test
        @DisplayName("validate: valid PDF document passes with correct canonical metadata")
        void testValidPdf() {
            ValidatedFileMetadata meta = validationService.validate(VALID_PDF_BYTES, "annual_report.pdf", "application/pdf");

            assertThat(meta.originalFilename()).isEqualTo("annual_report.pdf");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_PDF);
            assertThat(meta.size()).isEqualTo(VALID_PDF_BYTES.length);
            assertThat(meta.checksum()).isEqualTo(expectedSha256(VALID_PDF_BYTES));
            assertThat(meta.content()).isEqualTo(VALID_PDF_BYTES);
            assertThat(meta.openStream()).hasBinaryContent(VALID_PDF_BYTES);
        }

        @Test
        @DisplayName("validate: valid DOCX archive passes with correct canonical metadata")
        void testValidDocx() throws IOException {
            byte[] docxBytes = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>",
                    "word/document.xml", "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"/>"
            ));

            ValidatedFileMetadata meta = validationService.validate(docxBytes, "contract.docx", FileValidationService.MIME_DOCX);

            assertThat(meta.originalFilename()).isEqualTo("contract.docx");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_DOCX);
            assertThat(meta.size()).isEqualTo(docxBytes.length);
            assertThat(meta.checksum()).isEqualTo(expectedSha256(docxBytes));
        }

        @Test
        @DisplayName("validate: valid XLSX spreadsheet passes with correct canonical metadata")
        void testValidXlsx() throws IOException {
            byte[] xlsxBytes = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>",
                    "xl/workbook.xml", "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"/>"
            ));

            ValidatedFileMetadata meta = validationService.validate(xlsxBytes, "financials.xlsx", FileValidationService.MIME_XLSX);

            assertThat(meta.originalFilename()).isEqualTo("financials.xlsx");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_XLSX);
            assertThat(meta.size()).isEqualTo(xlsxBytes.length);
            assertThat(meta.checksum()).isEqualTo(expectedSha256(xlsxBytes));
        }

        @Test
        @DisplayName("validate: valid PPTX presentation passes with correct canonical metadata")
        void testValidPptx() throws IOException {
            byte[] pptxBytes = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>",
                    "ppt/presentation.xml", "<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"/>"
            ));

            ValidatedFileMetadata meta = validationService.validate(pptxBytes, "deck.pptx", FileValidationService.MIME_PPTX);

            assertThat(meta.originalFilename()).isEqualTo("deck.pptx");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_PPTX);
            assertThat(meta.size()).isEqualTo(pptxBytes.length);
            assertThat(meta.checksum()).isEqualTo(expectedSha256(pptxBytes));
        }

        @Test
        @DisplayName("validate: valid UTF-8 TXT passes with correct canonical metadata")
        void testValidTxt() {
            ValidatedFileMetadata meta = validationService.validate(VALID_TXT_BYTES, "notes.txt", "text/plain");

            assertThat(meta.originalFilename()).isEqualTo("notes.txt");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_TXT);
            assertThat(meta.size()).isEqualTo(VALID_TXT_BYTES.length);
            assertThat(meta.checksum()).isEqualTo(expectedSha256(VALID_TXT_BYTES));
        }

        @Test
        @DisplayName("validate: valid UTF-8 CSV passes with correct canonical metadata")
        void testValidCsv() {
            ValidatedFileMetadata meta = validationService.validate(VALID_CSV_BYTES, "data.csv", "text/csv");

            assertThat(meta.originalFilename()).isEqualTo("data.csv");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_CSV);
            assertThat(meta.size()).isEqualTo(VALID_CSV_BYTES.length);
            assertThat(meta.checksum()).isEqualTo(expectedSha256(VALID_CSV_BYTES));
        }

        @Test
        @DisplayName("validate: valid PNG image passes with correct canonical metadata")
        void testValidPng() {
            ValidatedFileMetadata meta = validationService.validate(VALID_PNG_BYTES, "diagram.png", "image/png");

            assertThat(meta.originalFilename()).isEqualTo("diagram.png");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_PNG);
            assertThat(meta.size()).isEqualTo(VALID_PNG_BYTES.length);
            assertThat(meta.checksum()).isEqualTo(expectedSha256(VALID_PNG_BYTES));
        }

        @Test
        @DisplayName("validate: valid JPG image passes with correct canonical metadata")
        void testValidJpg() {
            ValidatedFileMetadata meta = validationService.validate(VALID_JPEG_BYTES, "photo.jpg", "image/jpeg");

            assertThat(meta.originalFilename()).isEqualTo("photo.jpg");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_JPEG);
            assertThat(meta.size()).isEqualTo(VALID_JPEG_BYTES.length);
        }

        @Test
        @DisplayName("validate: valid JPEG image passes with correct canonical metadata")
        void testValidJpeg() {
            ValidatedFileMetadata meta = validationService.validate(VALID_JPEG_BYTES, "photo.jpeg", "image/jpeg");

            assertThat(meta.originalFilename()).isEqualTo("photo.jpeg");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_JPEG);
            assertThat(meta.size()).isEqualTo(VALID_JPEG_BYTES.length);
        }

        @Test
        @DisplayName("validate: Spring MockMultipartFile is supported seamlessly")
        void testValidMultipartFile() {
            MockMultipartFile file = new MockMultipartFile(
                    "file",
                    "document.pdf",
                    "application/pdf",
                    VALID_PDF_BYTES
            );

            ValidatedFileMetadata meta = validationService.validate(file);

            assertThat(meta.originalFilename()).isEqualTo("document.pdf");
            assertThat(meta.contentType()).isEqualTo("application/pdf");
            assertThat(meta.size()).isEqualTo(VALID_PDF_BYTES.length);
        }
    }

    @Nested
    @DisplayName("2. Empty and Oversized Files")
    class SizeLimitTests {

        @Test
        @DisplayName("validate: empty byte array rejected")
        void testEmptyByteArray() {
            assertThatThrownBy(() -> validationService.validate(new byte[0], "file.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File must not be empty");
        }

        @Test
        @DisplayName("validate: empty stream with 0 declared size rejected")
        void testZeroDeclaredSize() {
            ByteArrayInputStream stream = new ByteArrayInputStream(new byte[0]);
            assertThatThrownBy(() -> validationService.validate(stream, "file.pdf", "application/pdf", 0L))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File must not be empty");
        }

        @Test
        @DisplayName("validate: negative declared size rejected")
        void testNegativeDeclaredSize() {
            ByteArrayInputStream stream = new ByteArrayInputStream(VALID_PDF_BYTES);
            assertThatThrownBy(() -> validationService.validate(stream, "file.pdf", "application/pdf", -5L))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File size must not be negative");
        }

        @Test
        @DisplayName("validate: declared size exceeding 10 MiB rejected immediately")
        void testDeclaredSizeExceedingLimit() {
            long oversized = FileValidationService.MAX_FILE_SIZE_BYTES + 1L;
            ByteArrayInputStream stream = new ByteArrayInputStream(VALID_PDF_BYTES);
            assertThatThrownBy(() -> validationService.validate(stream, "file.pdf", "application/pdf", oversized))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("exceeds maximum permitted limit of 10 MiB");
        }

        @Test
        @DisplayName("validate: streaming byte count exceeding 10 MiB rejected even without declared size")
        void testStreamingExceedingLimit() {
            // Infinite stream that yields byte 'A'
            InputStream infiniteStream = new InputStream() {
                @Override
                public int read() {
                    return 'A';
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    for (int i = 0; i < len; i++) {
                        b[off + i] = 'A';
                    }
                    return len;
                }
            };

            assertThatThrownBy(() -> validationService.validate(infiniteStream, "huge.txt", "text/plain", null))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File stream exceeded maximum permitted limit of 10 MiB");
        }

        @Test
        @DisplayName("validate: stream length mismatch with declared size rejected")
        void testStreamLengthMismatch() {
            ByteArrayInputStream stream = new ByteArrayInputStream(VALID_PDF_BYTES);
            long declared = VALID_PDF_BYTES.length + 50L;

            assertThatThrownBy(() -> validationService.validate(stream, "file.pdf", "application/pdf", declared))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("does not match declared size");
        }
    }

    @Nested
    @DisplayName("3. Extension, MIME, and Signature Mismatches")
    class MismatchTests {

        @Test
        @DisplayName("validate: PDF extension with PNG magic bytes rejected")
        void testPdfExtensionWithPngContent() {
            assertThatThrownBy(() -> validationService.validate(VALID_PNG_BYTES, "spoofed.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File content does not match PDF signature");
        }

        @Test
        @DisplayName("validate: PNG extension with JPEG magic bytes rejected")
        void testPngExtensionWithJpegContent() {
            assertThatThrownBy(() -> validationService.validate(VALID_JPEG_BYTES, "spoofed.png", "image/png"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File content does not match PNG signature");
        }

        @Test
        @DisplayName("validate: JPG extension with PDF magic bytes rejected")
        void testJpegExtensionWithPdfContent() {
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "spoofed.jpg", "image/jpeg"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File content does not match JPEG signature");
        }

        @Test
        @DisplayName("validate: declared Content-Type mismatch rejected")
        void testDeclaredContentTypeMismatch() {
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "file.pdf", "image/png"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Declared Content-Type 'image/png' does not match permitted types");
        }

        @Test
        @DisplayName("validate: permitted MIME aliases accepted for PDF")
        void testPermittedMimeAliases() {
            ValidatedFileMetadata meta = validationService.validate(VALID_PDF_BYTES, "file.pdf", "application/x-pdf");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_PDF);
        }

        @Test
        @DisplayName("validate: Content-Type parameter like charset is stripped and accepted")
        void testContentTypeParameterStripped() {
            ValidatedFileMetadata meta = validationService.validate(VALID_TXT_BYTES, "file.txt", "text/plain; charset=UTF-8");
            assertThat(meta.contentType()).isEqualTo(FileValidationService.MIME_TXT);
        }

        @Test
        @DisplayName("validate: unsupported file extensions rejected")
        void testUnsupportedExtensions() {
            assertThatThrownBy(() -> validationService.validate(new byte[]{1, 2, 3}, "malware.exe", "application/octet-stream"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Unsupported file extension: '.exe'");

            assertThatThrownBy(() -> validationService.validate(new byte[]{1, 2, 3}, "script.sh", "text/x-sh"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Unsupported file extension: '.sh'");

            assertThatThrownBy(() -> validationService.validate(new byte[]{1, 2, 3}, "archive.zip", "application/zip"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Unsupported file extension: '.zip'");

            assertThatThrownBy(() -> validationService.validate(new byte[]{1, 2, 3}, "page.html", "text/html"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Unsupported file extension: '.html'");
        }

        @Test
        @DisplayName("validate: missing extension or trailing dot rejected")
        void testMissingExtension() {
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "document", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename must possess a valid file extension");

            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "document.", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename must possess a valid file extension");

            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, ".pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename must possess a valid file extension");
        }
    }

    @Nested
    @DisplayName("4. Plaintext UTF-8 and Binary Validation")
    class PlaintextTests {

        @Test
        @DisplayName("validate: TXT containing NUL byte (0x00) rejected")
        void testTxtWithNulByte() {
            byte[] badTxt = new byte[]{'H', 'e', 'l', 'l', 'o', 0x00, 'W', 'o', 'r', 'l', 'd'};
            assertThatThrownBy(() -> validationService.validate(badTxt, "test.txt", "text/plain"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("TXT file contains forbidden binary NUL byte at offset 5");
        }

        @Test
        @DisplayName("validate: CSV containing NUL byte (0x00) rejected")
        void testCsvWithNulByte() {
            byte[] badCsv = new byte[]{'a', ',', 'b', '\n', '1', ',', 0x00};
            assertThatThrownBy(() -> validationService.validate(badCsv, "test.csv", "text/csv"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("CSV file contains forbidden binary NUL byte");
        }

        @Test
        @DisplayName("validate: TXT containing invalid UTF-8 byte sequence rejected")
        void testTxtInvalidUtf8() {
            // Standalone continuation byte 0x80 is invalid leading UTF-8 byte
            byte[] badUtf8 = new byte[]{'H', 'e', 'l', 'l', 'o', (byte) 0x80, '!'};
            assertThatThrownBy(() -> validationService.validate(badUtf8, "test.txt", "text/plain"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("TXT file is not valid UTF-8 text");
        }

        @Test
        @DisplayName("validate: CSV containing invalid UTF-8 byte sequence rejected")
        void testCsvInvalidUtf8() {
            byte[] badUtf8 = new byte[]{'a', ',', (byte) 0xFF, '\n'};
            assertThatThrownBy(() -> validationService.validate(badUtf8, "test.csv", "text/csv"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("CSV file is not valid UTF-8 text");
        }
    }

    @Nested
    @DisplayName("5. Office OOXML Container Validation")
    class OfficeArchiveTests {

        @Test
        @DisplayName("validate: non-ZIP container rejected for Office document")
        void testOfficeNotZip() {
            byte[] nonZip = "This is not a zip file".getBytes(StandardCharsets.UTF_8);
            assertThatThrownBy(() -> validationService.validate(nonZip, "document.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("DOCX document does not have a valid ZIP/OOXML container header");
        }

        @Test
        @DisplayName("validate: corrupted ZIP container rejected")
        void testCorruptedZip() {
            byte[] corrupted = new byte[]{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00};
            assertThatThrownBy(() -> validationService.validate(corrupted, "document.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("DOCX archive is missing required '[Content_Types].xml' entry");
        }

        @Test
        @DisplayName("validate: DOCX missing [Content_Types].xml rejected")
        void testDocxMissingContentTypes() throws IOException {
            byte[] badDocx = createSyntheticZip(Map.of(
                    "word/document.xml", "<w:document/>"
            ));

            assertThatThrownBy(() -> validationService.validate(badDocx, "document.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("missing required '[Content_Types].xml' entry");
        }

        @Test
        @DisplayName("validate: DOCX missing word/document.xml rejected")
        void testDocxMissingDocumentXml() throws IOException {
            byte[] badDocx = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types/>"
            ));

            assertThatThrownBy(() -> validationService.validate(badDocx, "document.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("missing required document entry 'word/document.xml'");
        }

        @Test
        @DisplayName("validate: XLSX missing xl/workbook.xml rejected")
        void testXlsxMissingWorkbookXml() throws IOException {
            byte[] badXlsx = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types/>"
            ));

            assertThatThrownBy(() -> validationService.validate(badXlsx, "sheet.xlsx", FileValidationService.MIME_XLSX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("missing required document entry 'xl/workbook.xml'");
        }

        @Test
        @DisplayName("validate: PPTX missing ppt/presentation.xml rejected")
        void testPptxMissingPresentationXml() throws IOException {
            byte[] badPptx = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types/>"
            ));

            assertThatThrownBy(() -> validationService.validate(badPptx, "slides.pptx", FileValidationService.MIME_PPTX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("missing required document entry 'ppt/presentation.xml'");
        }

        @Test
        @DisplayName("validate: Zip-Slip path traversal inside OOXML archive rejected")
        void testZipSlipTraversal() throws IOException {
            byte[] slipArchive = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types/>",
                    "word/document.xml", "<w:document/>",
                    "../../evil.sh", "echo pwned"
            ));

            assertThatThrownBy(() -> validationService.validate(slipArchive, "slip.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("illegal entry path traversal");
        }

        @Test
        @DisplayName("validate: archive entry with leading slash rejected")
        void testLeadingSlashEntry() throws IOException {
            byte[] slashArchive = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types/>",
                    "word/document.xml", "<w:document/>",
                    "/root/file.txt", "data"
            ));

            assertThatThrownBy(() -> validationService.validate(slashArchive, "slash.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("illegal entry path traversal");
        }
    }

    @Nested
    @DisplayName("6. Arbitrary ZIP Files Renamed to Office Extensions")
    class RenamedZipTests {

        @Test
        @DisplayName("validate: arbitrary ZIP renamed to .docx rejected")
        void testArbitraryZipRenamedToDocx() throws IOException {
            byte[] normalZip = createSyntheticZip(Map.of(
                    "readme.txt", "This is just a text file inside a zip",
                    "data/test.bin", "binary"
            ));

            assertThatThrownBy(() -> validationService.validate(normalZip, "fake.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("missing required '[Content_Types].xml' entry");
        }

        @Test
        @DisplayName("validate: valid XLSX spreadsheet renamed to .docx rejected")
        void testXlsxRenamedToDocx() throws IOException {
            byte[] xlsxBytes = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types/>",
                    "xl/workbook.xml", "<workbook/>"
            ));

            assertThatThrownBy(() -> validationService.validate(xlsxBytes, "mismatched.docx", FileValidationService.MIME_DOCX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("missing required document entry 'word/document.xml'");
        }

        @Test
        @DisplayName("validate: valid DOCX document renamed to .pptx rejected")
        void testDocxRenamedToPptx() throws IOException {
            byte[] docxBytes = createSyntheticZip(Map.of(
                    "[Content_Types].xml", "<Types/>",
                    "word/document.xml", "<w:document/>"
            ));

            assertThatThrownBy(() -> validationService.validate(docxBytes, "mismatched.pptx", FileValidationService.MIME_PPTX))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("missing required document entry 'ppt/presentation.xml'");
        }
    }

    @Nested
    @DisplayName("7. Filename Sanitization and Validation")
    class FilenameTests {

        @Test
        @DisplayName("validate: directory traversal '..' in filename rejected")
        void testFilenameTraversal() {
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "../../secret.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename contains illegal path traversal sequence: '..'");

            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "..\\secret.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename contains illegal path traversal sequence: '..'");
        }

        @Test
        @DisplayName("validate: NUL byte in filename rejected")
        void testFilenameWithNulByte() {
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "test\0.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename contains illegal NUL character");
        }

        @Test
        @DisplayName("validate: control characters in filename rejected")
        void testFilenameWithControlChars() {
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "test\n.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename contains illegal control character");

            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "test\r.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename contains illegal control character");

            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "test\t.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename contains illegal control character");
        }

        @Test
        @DisplayName("validate: filename exceeding 255 characters rejected")
        void testFilenameExceeding255() {
            String longName = "a".repeat(252) + ".pdf"; // 252 + 4 = 256 characters
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, longName, "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename exceeds maximum permitted length of 255 characters");
        }

        @Test
        @DisplayName("validate: filename of exactly 255 characters accepted")
        void testFilenameExactly255() {
            String maxName = "a".repeat(251) + ".pdf"; // 251 + 4 = 255 characters
            ValidatedFileMetadata meta = validationService.validate(VALID_PDF_BYTES, maxName, "application/pdf");
            assertThat(meta.originalFilename()).isEqualTo(maxName);
        }

        @Test
        @DisplayName("validate: null, empty, or whitespace-only filename rejected")
        void testNullOrBlankFilename() {
            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, null, "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename must not be null or blank");

            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename must not be null or blank");

            assertThatThrownBy(() -> validationService.validate(VALID_PDF_BYTES, "   ", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Filename must not be null or blank");
        }

        @Test
        @DisplayName("validate: path prefixes (Unix and Windows) stripped to safe basename")
        void testPathStripping() {
            ValidatedFileMetadata unixMeta = validationService.validate(VALID_PDF_BYTES, "/home/alice/uploads/report.pdf", "application/pdf");
            assertThat(unixMeta.originalFilename()).isEqualTo("report.pdf");

            ValidatedFileMetadata winMeta = validationService.validate(VALID_PDF_BYTES, "C:\\Users\\Alice\\Documents\\report.pdf", "application/pdf");
            assertThat(winMeta.originalFilename()).isEqualTo("report.pdf");
        }
    }

    @Nested
    @DisplayName("8. Stream Limits and Malformed Input")
    class StreamAndInputTests {

        @Test
        @DisplayName("validate: null input stream rejected")
        void testNullInputStream() {
            assertThatThrownBy(() -> validationService.validate((InputStream) null, "test.pdf", "application/pdf", 100L))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Input stream must not be null");
        }

        @Test
        @DisplayName("validate: null byte array rejected")
        void testNullByteArray() {
            assertThatThrownBy(() -> validationService.validate((byte[]) null, "test.pdf", "application/pdf"))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("File content must not be null");
        }

        @Test
        @DisplayName("validate: null MultipartFile rejected")
        void testNullMultipartFile() {
            assertThatThrownBy(() -> validationService.validate((MockMultipartFile) null))
                    .isInstanceOf(FileValidationException.class)
                    .hasMessageContaining("Upload file payload must not be null");
        }

        @Test
        @DisplayName("validate: SHA-256 matches exact cryptographic standard")
        void testSha256Integrity() {
            ValidatedFileMetadata meta = validationService.validate(VALID_PDF_BYTES, "test.pdf", "application/pdf");
            assertThat(meta.checksum()).isEqualTo(expectedSha256(VALID_PDF_BYTES));
            assertThat(meta.checksum()).matches("^[a-f0-9]{64}$");
        }
    }

    // --- Helper Utilities ---

    private static byte[] createSyntheticZip(Map<String, String> entries) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                ZipEntry ze = new ZipEntry(entry.getKey());
                zos.putNextEntry(ze);
                zos.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        }
        return baos.toByteArray();
    }

    private static String expectedSha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
