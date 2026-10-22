package com.trustvault.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Controller managing web authentication views.
 *
 * Security Requirements:
 * - Renders the custom TrustVault login page at /login.
 * - Public self-registration is explicitly disabled.
 * - Relies on Spring Security formLogin processing for credential verification and session fixation protection.
 */
@Controller
public class AuthController {

    /**
     * Renders the custom TrustVault login page.
     *
     * @return the Thymeleaf template view name 'login'
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
