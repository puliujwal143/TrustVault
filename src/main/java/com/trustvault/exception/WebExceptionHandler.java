package com.trustvault.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustvault.controller.AuditViewController;
import com.trustvault.controller.AuthController;
import com.trustvault.controller.DocumentViewController;
import com.trustvault.dto.ErrorResponseDto;
import com.trustvault.storage.FileValidationException;
import com.trustvault.storage.StorageException;
import com.trustvault.storage.StorageFileNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Controller advice dedicated to web view controllers (SSR Thymeleaf).
 *
 * Responsibilities:
 * - Intercept exceptions originating from HTML view navigation routes (e.g. /documents/{id}).
 * - Render user-friendly HTML error views instead of raw JSON responses.
 * - Suppress sensitive implementation details, internal paths, and stack traces.
 * - Enforce consistent HTTP status codes (403 Forbidden, 404 Not Found, 500 Internal Server Error).
 * - Gracefully format JSON only if a client explicitly requests application/json without text/html.
 */
@ControllerAdvice(assignableTypes = {
        DocumentViewController.class,
        AuditViewController.class,
        AuthController.class
})
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(WebExceptionHandler.class);
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    @ExceptionHandler(AccessDeniedException.class)
    public ModelAndView handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        log.warn("Web access denied on path: {}", request != null ? request.getRequestURI() : "unknown");

        return dispatchError(
                HttpStatus.FORBIDDEN,
                "Access Denied",
                "You do not have permission to access this document or perform this action. If you believe this is an error, please request access from the document owner.",
                request,
                response
        );
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ModelAndView handleResourceNotFound(
            ResourceNotFoundException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        log.info("Web resource not found on path: {}", request != null ? request.getRequestURI() : "unknown");

        return dispatchError(
                HttpStatus.NOT_FOUND,
                "Document Not Found",
                "The requested document does not exist, has been removed, or you do not have permission to view it.",
                request,
                response
        );
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ModelAndView handleNoResourceFound(
            NoResourceFoundException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        return dispatchError(
                HttpStatus.NOT_FOUND,
                "Resource Not Found",
                "The requested page or resource could not be found.",
                request,
                response
        );
    }

    @ExceptionHandler(StorageFileNotFoundException.class)
    public ModelAndView handleStorageFileNotFound(
            StorageFileNotFoundException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        log.warn("Storage file not found on path {}: {}", request != null ? request.getRequestURI() : "unknown", ex.getMessage());

        return dispatchError(
                HttpStatus.NOT_FOUND,
                "Document File Not Found",
                "The requested document file could not be found or has not yet been uploaded.",
                request,
                response
        );
    }

    @ExceptionHandler(FileValidationException.class)
    public ModelAndView handleFileValidation(
            FileValidationException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        log.warn("Web file validation failed: {}", ex.getMessage());

        return dispatchError(
                HttpStatus.BAD_REQUEST,
                "Invalid Document File",
                ex.getMessage(),
                request,
                response
        );
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ModelAndView handleMaxUploadSize(
            MaxUploadSizeExceededException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        return dispatchError(
                HttpStatus.PAYLOAD_TOO_LARGE,
                "Payload Too Large",
                "Upload payload exceeds the maximum permitted size limit of 10 MiB.",
                request,
                response
        );
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ModelAndView handleIllegalArgument(
            IllegalArgumentException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        return dispatchError(
                HttpStatus.BAD_REQUEST,
                "Invalid Request",
                ex.getMessage(),
                request,
                response
        );
    }

    @ExceptionHandler(StorageException.class)
    public ModelAndView handleStorageException(
            StorageException ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        log.error("Web storage error processing {}: {}", request != null ? request.getRequestURI() : "unknown", ex.getMessage(), ex);

        return dispatchError(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Unexpected Server Error",
                "A storage error occurred while processing the document file. Please try again later.",
                request,
                response
        );
    }

    @ExceptionHandler(Exception.class)
    public ModelAndView handleGenericException(
            Exception ex,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        log.error("Unhandled web exception processing {}: {}", request != null ? request.getRequestURI() : "unknown", ex.getMessage(), ex);

        return dispatchError(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Unexpected Server Error",
                "An unexpected internal error occurred. Please try again later or contact your system administrator.",
                request,
                response
        );
    }

    private ModelAndView dispatchError(
            HttpStatus status,
            String heading,
            String message,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        if (isJsonOnlyRequest(request) && response != null) {
            response.setStatus(status.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            ErrorResponseDto errorDto = ErrorResponseDto.of(
                    status.value(),
                    status.getReasonPhrase(),
                    heading.equals("Unexpected Server Error") ? "An unexpected internal error occurred. Please contact system administrator." : message,
                    request != null ? request.getRequestURI() : ""
            );
            objectMapper.writeValue(response.getWriter(), errorDto);
            return null;
        }

        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(status);
        mav.addObject("status", status.value());
        mav.addObject("error", status.getReasonPhrase());
        mav.addObject("heading", heading);
        mav.addObject("message", message);
        mav.addObject("path", request != null ? request.getRequestURI() : "");
        mav.addObject("pageTitle", heading + " — TrustVault");
        mav.addObject("activeTab", "all");
        return mav;
    }

    private boolean isJsonOnlyRequest(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        String accept = request.getHeader(HttpHeaders.ACCEPT);
        return accept != null && accept.contains(MediaType.APPLICATION_JSON_VALUE) && !accept.contains(MediaType.TEXT_HTML_VALUE);
    }
}
