package com.trustvault.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Listens for Spring Security authentication lifecycle events and coordinates
 * failure tracking and success resets with {@link AuthenticationRateLimiter}.
 *
 * <p>Security Guarantees:
 * <ul>
 *   <li>Safely captures failed credentials without logging passwords, tokens, or hashes.</li>
 *   <li>Resolves client IP securely without trusting arbitrary client-supplied headers.</li>
 *   <li>Resets target failure counters immediately upon successful authentication.</li>
 * </ul>
 */
@Component
public class AuthenticationEventListener {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationEventListener.class);

    private final AuthenticationRateLimiter rateLimiter;

    public AuthenticationEventListener(AuthenticationRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    /**
     * Intercepts authentication failure events published by Spring Security
     * (e.g. BadCredentialsException, DisabledException) across both form login and HTTP Basic.
     */
    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        Authentication auth = event.getAuthentication();
        if (auth == null) {
            return;
        }

        String username = auth.getName();
        String clientIp = resolveIp(auth);

        rateLimiter.recordFailure(clientIp, username);
        log.warn("Authentication failure tracked for username '{}' from IP '{}' (type: {})",
                AuthenticationRateLimiter.sanitizeForLog(username), clientIp, event.getException().getClass().getSimpleName());
    }

    /**
     * Intercepts authentication success events published by Spring Security
     * and resets the failure counter for the authenticated user and IP.
     */
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Authentication auth = event.getAuthentication();
        if (auth == null) {
            return;
        }

        String username = auth.getName();
        String clientIp = resolveIp(auth);

        rateLimiter.recordSuccess(clientIp, username);
    }

    private String resolveIp(Authentication auth) {
        if (auth.getDetails() instanceof WebAuthenticationDetails webDetails) {
            String remoteAddress = webDetails.getRemoteAddress();
            if (remoteAddress != null && !remoteAddress.isBlank()) {
                return remoteAddress.trim();
            }
        }

        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            String remoteAddr = request.getRemoteAddr();
            if (remoteAddr != null && !remoteAddr.isBlank()) {
                return remoteAddr.trim();
            }
        }

        return "127.0.0.1";
    }
}
