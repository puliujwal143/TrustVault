package com.trustvault.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Servlet filter intercepting authentication requests to enforce rate limiting and brute-force throttling.
 *
 * <p>Execution Boundary:
 * <ul>
 *   <li>Positioned before {@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter}
 *       in the Spring Security filter chain.</li>
 *   <li>Intercepts form login submissions ({@code POST /login}) and HTTP Basic headers
 *       ({@code Authorization: Basic ...}).</li>
 *   <li>If the client IP or target account has exceeded failure thresholds, requests are rejected immediately
 *       without invoking BCrypt password evaluation, defending against CPU starvation.</li>
 *   <li>Bypasses public probes ({@code /api/health}) and static resources ({@code /css/**}, {@code /js/**}).</li>
 * </ul>
 */
@Component
public class AuthenticationRateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationRateLimitingFilter.class);

    private final AuthenticationRateLimiter rateLimiter;

    public AuthenticationRateLimitingFilter(AuthenticationRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null) {
            return false;
        }

        // Exclude static resources and error dispatch
        if (path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/")
                || "/favicon.ico".equals(path)
                || "/error".equals(path)) {
            return true;
        }

        // /api/health probe is bypassed for ordinary unauthenticated health checks.
        // However, if a request attaches an Authorization header, it must be evaluated
        // by the rate limiter to prevent unthrottled brute-force or CPU starvation attacks.
        if ("/api/health".equals(path)) {
            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            return authHeader == null || !authHeader.regionMatches(true, 0, "Basic ", 0, 6);
        }

        return false;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String clientIp = resolveClientIp(request);

        // 1. Check Form Login submissions: POST /login
        if ("POST".equalsIgnoreCase(request.getMethod()) && isLoginPath(request)) {
            String username = request.getParameter("username");
            if (rateLimiter.isBlocked(clientIp, username)) {
                long remainingSeconds = rateLimiter.getRemainingBlockSeconds(clientIp, username);
                log.warn("Form login blocked by rate limiter for IP '{}' and username '{}' (remaining: {}s)",
                        clientIp, username, remainingSeconds);

                response.setHeader("Retry-After", String.valueOf(remainingSeconds));
                response.sendRedirect(request.getContextPath() + "/login?blocked");
                return;
            }
        }

        // 2. Check HTTP Basic authentication headers: Authorization: Basic <base64>
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            String basicUsername = extractBasicAuthUsername(request);
            if (rateLimiter.isBlocked(clientIp, basicUsername)) {
                long remainingSeconds = rateLimiter.getRemainingBlockSeconds(clientIp, basicUsername);
                log.warn("HTTP Basic request blocked by rate limiter for IP '{}' and username '{}' (remaining: {}s)",
                        clientIp, basicUsername, remainingSeconds);

                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value()); // HTTP 429
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setHeader("Retry-After", String.valueOf(remainingSeconds));
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());

                String jsonBody = String.format(
                        "{\"status\":429,\"error\":\"Too Many Requests\",\"message\":\"Too many failed authentication attempts. Please try again in %d seconds.\"}",
                        remainingSeconds
                );
                response.getWriter().write(jsonBody);
                response.getWriter().flush();
                return;
            }
        }

        // Request is not rate-limited: proceed through normal filter chain
        filterChain.doFilter(request, response);
    }

    private boolean isLoginPath(HttpServletRequest request) {
        String servletPath = request.getServletPath();
        if ("/login".equals(servletPath)) {
            return true;
        }
        String requestUri = request.getRequestURI();
        return requestUri != null && requestUri.endsWith("/login");
    }

    /**
     * Resolves client IP safely from the request socket without blindly trusting client-supplied headers.
     */
    public static String resolveClientIp(HttpServletRequest request) {
        if (request == null) {
            return "127.0.0.1";
        }
        String remoteAddr = request.getRemoteAddr();
        return (remoteAddr != null && !remoteAddr.isBlank()) ? remoteAddr.trim() : "127.0.0.1";
    }

    /**
     * Safely extracts only the username component from an HTTP Basic Authorization header.
     * Never prints, stores, or extracts the password portion.
     */
    public static String extractBasicAuthUsername(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }
        try {
            String base64 = authHeader.substring(6).trim();
            byte[] decoded = Base64.getDecoder().decode(base64);
            String credentials = new String(decoded, StandardCharsets.UTF_8);
            int colonIndex = credentials.indexOf(':');
            if (colonIndex != -1) {
                return credentials.substring(0, colonIndex).trim();
            }
        } catch (Exception ignored) {
            // Malformed base64 header
        }
        return null;
    }
}
