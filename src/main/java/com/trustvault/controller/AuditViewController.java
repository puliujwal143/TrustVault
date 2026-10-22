package com.trustvault.controller;

import com.trustvault.audit.AuditEvent;
import com.trustvault.audit.AuditOutcome;
import com.trustvault.dto.AuditItemViewModel;
import com.trustvault.entity.Role;
import com.trustvault.service.AuditService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Spring MVC controller managing the secure audit history view.
 *
 * Security Requirements:
 * - Default deny: all requests require an authenticated session (enforced by SecurityConfig).
 * - Current user resolved strictly from the authenticated Spring Security principal.
 * - Non-admin users are strictly restricted to their own audit records.
 *   URL parameter tampering attempting to view another user's audit records is rejected with AccessDeniedException.
 * - Administrators with ROLE_ADMIN are permitted to review all platform audit events or filter by actor.
 * - Exposes only sanitized AuditItemViewModel instances to Thymeleaf, preventing exposure of sensitive
 *   blob UUIDs, physical paths, or internal tokens.
 */
@Controller
public class AuditViewController {

    private static final int DEFAULT_PAGE_SIZE = 20;
    private static final int MAX_PAGE_SIZE = 100;

    private final AuditService auditService;

    public AuditViewController(AuditService auditService) {
        this.auditService = auditService;
    }

    /**
     * Renders the audit history page with paginated events, outcome metrics, and actor filtering.
     *
     * @param page           0-indexed page number (default 0)
     * @param size           page size (default 20, max 100)
     * @param actor          optional actor username filter
     * @param model          Thymeleaf UI model
     * @param authentication authenticated user principal
     * @return the 'audit/list' template view
     */
    @GetMapping("/audit")
    public String showAuditHistory(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "20") int size,
            @RequestParam(value = "actor", required = false) String actor,
            Model model,
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equalsIgnoreCase(authentication.getName())) {
            return "redirect:/login";
        }

        String currentUsername = authentication.getName();

        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(Role.ROLE_ADMIN.name()));

        // Access Control: Non-admin users must not view other users' audit trails
        String targetActor;
        if (isAdmin) {
            targetActor = (actor != null && !actor.isBlank()) ? actor.trim() : null;
        } else {
            if (actor != null && !actor.isBlank() && !actor.trim().equalsIgnoreCase(currentUsername)) {
                throw new AccessDeniedException("Access is denied. You are not authorized to view audit events for another user.");
            }
            targetActor = currentUsername;
        }

        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        Pageable pageable = PageRequest.of(boundedPage, boundedSize, Sort.by(Sort.Direction.DESC, "timestamp", "id"));

        Page<AuditEvent> eventPage;
        long totalCount;
        long successCount;
        long deniedCount;

        if (targetActor != null) {
            eventPage = auditService.getEventsForActor(targetActor, pageable);
            totalCount = auditService.getEventCountForActor(targetActor);
            successCount = auditService.getEventCountForActorAndOutcome(targetActor, AuditOutcome.SUCCESS);
            deniedCount = auditService.getEventCountForActorAndOutcome(targetActor, AuditOutcome.DENIED);
        } else {
            eventPage = auditService.getAllEvents(pageable);
            totalCount = auditService.getEventCount();
            successCount = auditService.getEventCountByOutcome(AuditOutcome.SUCCESS);
            deniedCount = auditService.getEventCountByOutcome(AuditOutcome.DENIED);
        }

        Page<AuditItemViewModel> viewModelPage = eventPage.map(AuditItemViewModel::from);

        model.addAttribute("events", viewModelPage.getContent());
        model.addAttribute("currentPage", viewModelPage.getNumber());
        model.addAttribute("totalPages", viewModelPage.getTotalPages());
        model.addAttribute("totalElements", viewModelPage.getTotalElements());
        model.addAttribute("hasNext", viewModelPage.hasNext());
        model.addAttribute("hasPrevious", viewModelPage.hasPrevious());
        model.addAttribute("selectedActor", targetActor);
        model.addAttribute("isAdmin", isAdmin);
        model.addAttribute("totalCount", totalCount);
        model.addAttribute("successCount", successCount);
        model.addAttribute("deniedCount", deniedCount);
        model.addAttribute("activeTab", "audit");
        model.addAttribute("pageTitle", "Audit History");

        return "audit/list";
    }
}
