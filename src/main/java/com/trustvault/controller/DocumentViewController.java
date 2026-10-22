package com.trustvault.controller;

import com.trustvault.dto.CreateDocumentForm;
import com.trustvault.dto.DocumentDetailViewModel;
import com.trustvault.dto.DocumentItemViewModel;
import com.trustvault.dto.ShareDocumentForm;
import com.trustvault.dto.UpdateDocumentForm;
import com.trustvault.entity.Document;
import com.trustvault.entity.DocumentShare;
import com.trustvault.entity.SharePermission;
import com.trustvault.entity.User;
import com.trustvault.exception.ResourceNotFoundException;
import com.trustvault.repository.DocumentShareRepository;
import com.trustvault.repository.UserRepository;
import com.trustvault.service.DocumentService;
import com.trustvault.service.DocumentShareService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Spring MVC controller managing the document dashboard, creation, and detail views.
 *
 * Security Requirements:
 * - Default deny: all endpoints require authenticated sessions (enforced by SecurityConfig).
 * - Username is ALWAYS obtained from the authenticated Spring Security context;
 *   client-supplied user identifiers are never accepted.
 * - Entities are transformed into safe view models (DocumentItemViewModel, DocumentDetailViewModel)
 *   before rendering, strictly adhering to spring.jpa.open-in-view=false and preventing exposure
 *   of sensitive blob UUIDs, physical paths, or checksums.
 * - Enforces Post/Redirect/Get (PRG) pattern on document creation, sharing, and revocation with CSRF validation.
 * - Preserves anti-IDOR defense by delegating document retrieval to DocumentService.getDocument(id, username).
 */
@Controller
public class DocumentViewController {

    private final DocumentService documentService;
    private final DocumentShareRepository documentShareRepository;
    private final DocumentShareService documentShareService;
    private final UserRepository userRepository;

    public DocumentViewController(
            DocumentService documentService,
            DocumentShareRepository documentShareRepository,
            DocumentShareService documentShareService) {
        this(documentService, documentShareRepository, documentShareService, null);
    }

    @Autowired
    public DocumentViewController(
            DocumentService documentService,
            DocumentShareRepository documentShareRepository,
            DocumentShareService documentShareService,
            UserRepository userRepository) {
        this.documentService = documentService;
        this.documentShareRepository = documentShareRepository;
        this.documentShareService = documentShareService;
        this.userRepository = userRepository;
    }

    /**
     * Root redirect: redirects authenticated users to the primary document dashboard.
     */
    @GetMapping("/")
    public String root() {
        return "redirect:/documents";
    }

    /**
     * Renders the document dashboard with accessible documents, metrics, and filter tabs.
     *
     * @param filter         optional view filter ('all', 'owned', 'shared')
     * @param model          Thymeleaf UI model
     * @param authentication authenticated user principal
     * @return the 'documents/list' template view
     */
    @GetMapping("/documents")
    public String listDocuments(
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "q", required = false) String query,
            @RequestParam(value = "owner", required = false) String owner,
            @RequestParam(value = "fromDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate fromDate,
            @RequestParam(value = "toDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate toDate,
            Model model,
            Authentication authentication) {

        String username = authentication != null ? authentication.getName() : null;
        if (username == null) {
            return "redirect:/login";
        }

        populateDashboardModel(model, username, filter, query, owner, fromDate, toDate);

        if (!model.containsAttribute("createDocumentForm")) {
            model.addAttribute("createDocumentForm", new CreateDocumentForm());
        }

        return "documents/list";
    }

    /**
     * Renders detailed metadata, permission indicators, attached file information,
     * and access grants for a specific document.
     *
     * Security & Authorization Enforcement:
     * - The requesting username is obtained strictly from the authenticated Spring Security principal.
     * - Document authorization is evaluated by DocumentService.getDocument(id, username), which enforces
     *   READ permission and anti-IDOR defense (unshared callers receive 404 ResourceNotFoundException).
     * - Entities are mapped to a sanitized DocumentDetailViewModel that strictly omits physical storage
     *   keys, internal checksums, and filesystem paths.
     * - Active share grants are loaded and displayed ONLY if the caller is the verified OWNER.
     *
     * @param id             the document ID
     * @param model          Thymeleaf UI model
     * @param authentication authenticated user principal
     * @return the 'documents/detail' template view
     */
    @GetMapping("/documents/{id}")
    public String showDocument(
            @PathVariable("id") Long id,
            @RequestParam(value = "uploadSuccess", required = false) String uploadSuccess,
            @RequestParam(value = "uploadError", required = false) String uploadError,
            Model model,
            Authentication authentication) {

        String username = authentication != null ? authentication.getName() : null;
        if (username == null) {
            return "redirect:/login";
        }

        Document document = documentService.getDocument(id, username);

        boolean isOwner = document.getOwner() != null && document.getOwner().getUsername().equalsIgnoreCase(username);
        String permissionLabel;
        List<DocumentShare> shares = Collections.emptyList();
        List<String> availableUsers = Collections.emptyList();

        if (isOwner) {
            permissionLabel = "OWNER";
            shares = documentShareService.listShares(id, username);
            if (userRepository != null) {
                availableUsers = userRepository.findAll().stream()
                        .filter(u -> u.isEnabled() && !u.getUsername().equalsIgnoreCase(username))
                        .map(User::getUsername)
                        .sorted()
                        .toList();
            }
        } else {
            permissionLabel = documentShareRepository.findByDocumentIdAndGranteeUsername(id, username)
                    .map(s -> s.getPermission().name())
                    .orElse("READ");
        }

        DocumentDetailViewModel viewModel = DocumentDetailViewModel.from(document, username, permissionLabel, shares);
        model.addAttribute("document", viewModel);
        model.addAttribute("availableUsers", availableUsers);
        model.addAttribute("pageTitle", viewModel.title());
        model.addAttribute("activeTab", isOwner ? "owned" : "shared");

        if (!model.containsAttribute("shareDocumentForm")) {
            model.addAttribute("shareDocumentForm", new ShareDocumentForm());
        }

        if (!model.containsAttribute("updateDocumentForm")) {
            model.addAttribute("updateDocumentForm", new UpdateDocumentForm(document.getTitle(), document.getDescription()));
        }

        if (uploadSuccess != null && !uploadSuccess.isBlank()) {
            model.addAttribute("successMessage", "File '" + uploadSuccess.trim() + "' was successfully attached.");
        }
        if (uploadError != null && !uploadError.isBlank()) {
            model.addAttribute("errorMessage", uploadError.trim());
        }

        return "documents/detail";
    }

    /**
     * Handles document sharing grant or update form submissions.
     *
     * Security & Authorization Enforcement:
     * - The requesting username is obtained strictly from the authenticated Spring Security principal.
     * - Delegates to DocumentShareService.grantAccess(), which acquires a pessimistic write lock and
     *   enforces that only the document owner may grant shares. Grantees attempting to share receive 403 Forbidden;
     *   unshared callers receive 404 Not Found (anti-IDOR).
     * - Enforces Post/Redirect/Get (PRG) pattern with CSRF validation.
     *
     * @param id                 the document ID
     * @param form               form backing object or request parameters
     * @param granteeUsername    optional explicit grantee username param
     * @param usernameParam      optional fallback username param
     * @param permission         optional permission level
     * @param authentication     authenticated user principal
     * @param redirectAttributes flash attributes for PRG redirect
     * @return redirect to /documents/{id}
     */
    @PostMapping("/documents/{id}/shares")
    public String shareDocument(
            @PathVariable("id") Long id,
            @ModelAttribute ShareDocumentForm form,
            @RequestParam(value = "granteeUsername", required = false) String granteeUsername,
            @RequestParam(value = "username", required = false) String usernameParam,
            @RequestParam(value = "permission", required = false) SharePermission permission,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {

        String currentUsername = authentication != null ? authentication.getName() : null;
        if (currentUsername == null) {
            return "redirect:/login";
        }

        String targetGrantee = form != null && form.getGranteeUsername() != null && !form.getGranteeUsername().isBlank()
                ? form.getGranteeUsername().trim()
                : (granteeUsername != null && !granteeUsername.isBlank()
                        ? granteeUsername.trim()
                        : (usernameParam != null ? usernameParam.trim() : ""));

        SharePermission targetPerm = form != null && form.getPermission() != null
                ? form.getPermission()
                : (permission != null ? permission : SharePermission.READ);

        if (targetGrantee.isBlank()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Recipient username is required.");
            return "redirect:/documents/" + id;
        }

        try {
            boolean isUpdate = documentShareRepository.findByDocumentIdAndGranteeUsername(id, targetGrantee).isPresent();
            DocumentShare share = documentShareService.grantAccess(id, targetGrantee, targetPerm, currentUsername);

            if (isUpdate) {
                redirectAttributes.addFlashAttribute("successMessage",
                        "Share permission for user '" + share.getGrantee().getUsername() + "' was successfully updated to " + share.getPermission().name() + ".");
            } else {
                redirectAttributes.addFlashAttribute("successMessage",
                        "Document was successfully shared with user '" + share.getGrantee().getUsername() + "' (" + share.getPermission().name() + ").");
            }
        } catch (IllegalArgumentException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
        }

        return "redirect:/documents/" + id;
    }

    /**
     * Handles document share revocation form submissions.
     *
     * Security & Authorization Enforcement:
     * - The requesting username is obtained strictly from the authenticated Spring Security principal.
     * - Delegates to DocumentShareService.revokeAccess(), which acquires a pessimistic write lock and
     *   enforces that only the document owner may revoke shares. Grantees attempting to revoke receive 403 Forbidden;
     *   unshared callers receive 404 Not Found (anti-IDOR).
     * - Enforces Post/Redirect/Get (PRG) pattern with CSRF validation.
     *
     * @param id                 the document ID
     * @param pathGrantee        optional grantee username from URL path
     * @param paramGrantee       grantee username from form parameter
     * @param paramUsername      optional fallback username param
     * @param authentication     authenticated user principal
     * @param redirectAttributes flash attributes for PRG redirect
     * @return redirect to /documents/{id}
     */
    @RequestMapping(value = {"/documents/{id}/shares/revoke", "/documents/{id}/shares/{granteeUsername}/revoke", "/documents/{id}/shares/{granteeUsername}"}, method = {RequestMethod.POST, RequestMethod.DELETE})
    public String revokeShare(
            @PathVariable("id") Long id,
            @PathVariable(value = "granteeUsername", required = false) String pathGrantee,
            @RequestParam(value = "granteeUsername", required = false) String paramGrantee,
            @RequestParam(value = "username", required = false) String paramUsername,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {

        String currentUsername = authentication != null ? authentication.getName() : null;
        if (currentUsername == null) {
            return "redirect:/login";
        }

        String targetGrantee = (paramGrantee != null && !paramGrantee.isBlank())
                ? paramGrantee.trim()
                : (pathGrantee != null && !pathGrantee.isBlank()
                        ? pathGrantee.trim()
                        : (paramUsername != null ? paramUsername.trim() : ""));

        if (targetGrantee.isBlank()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Grantee username is required.");
            return "redirect:/documents/" + id;
        }

        try {
            documentShareService.revokeAccess(id, targetGrantee, currentUsername);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Access for user '" + targetGrantee + "' was successfully revoked.");
        } catch (IllegalArgumentException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
        } catch (ResourceNotFoundException ex) {
            if (ex.getMessage() != null && ex.getMessage().startsWith("No active share grant")) {
                redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
            } else {
                throw ex;
            }
        }

        return "redirect:/documents/" + id;
    }

    /**
     * Secure document creation form handler.
     *
     * Validates input bounds, verifies authenticated user identity from SecurityContext,
     * delegates to DocumentService with transactional audit recording, and applies
     * the Post/Redirect/Get pattern.
     *
     * @param form               submitted form payload
     * @param bindingResult      validation results
     * @param filter             current filter state for preservation on error
     * @param model              Thymeleaf model for error rendering
     * @param authentication     authenticated user principal
     * @param redirectAttributes flash attributes for PRG redirect
     * @return redirect to /documents on success or re-renders form on validation failure
     */
    @PostMapping("/documents")
    public String createDocument(
            @Valid @ModelAttribute("createDocumentForm") CreateDocumentForm form,
            BindingResult bindingResult,
            @RequestParam(value = "filter", required = false) String filter,
            Model model,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {

        String username = authentication != null ? authentication.getName() : null;
        if (username == null) {
            return "redirect:/login";
        }

        if (bindingResult.hasErrors()) {
            populateDashboardModel(model, username, filter, null, null, null, null);
            model.addAttribute("modalOpen", true);
            return "documents/list";
        }

        try {
            Document created = documentService.createDocument(form.getTitle(), form.getDescription(), username);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Document '" + created.getTitle() + "' was successfully created.");
            return "redirect:/documents";
        } catch (IllegalArgumentException | IllegalStateException ex) {
            bindingResult.reject("creationFailed", ex.getMessage());
            populateDashboardModel(model, username, filter, null, null, null, null);
            model.addAttribute("modalOpen", true);
            return "documents/list";
        }
    }

    /**
     * Handles document metadata modification requests (owner or EDIT collaborator).
     *
     * @param id                 the document ID
     * @param form               form backing object with title and description
     * @param bindingResult      validation results
     * @param authentication     authenticated user principal
     * @param redirectAttributes flash attributes for PRG redirect
     * @return redirect to /documents/{id}
     */
    @PostMapping(value = {"/documents/{id}/edit", "/documents/{id}"})
    public String updateDocument(
            @PathVariable("id") Long id,
            @Valid @ModelAttribute("updateDocumentForm") UpdateDocumentForm form,
            BindingResult bindingResult,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {

        String currentUsername = authentication != null ? authentication.getName() : null;
        if (currentUsername == null) {
            return "redirect:/login";
        }

        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    bindingResult.getFieldError() != null ? bindingResult.getFieldError().getDefaultMessage() : "Invalid document input.");
            return "redirect:/documents/" + id;
        }

        try {
            documentService.updateDocument(id, form.getTitle(), form.getDescription(), currentUsername);
            redirectAttributes.addFlashAttribute("successMessage", "Document details were successfully updated.");
        } catch (IllegalArgumentException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
        }

        return "redirect:/documents/" + id;
    }

    /**
     * Handles document deletion requests (owner-only).
     *
     * @param id                 the document ID
     * @param authentication     authenticated user principal
     * @param redirectAttributes flash attributes for PRG redirect
     * @return redirect to /documents on success
     */
    @RequestMapping(value = {"/documents/{id}/delete", "/documents/{id}"}, method = {RequestMethod.POST, RequestMethod.DELETE})
    public String deleteDocument(
            @PathVariable("id") Long id,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {

        String currentUsername = authentication != null ? authentication.getName() : null;
        if (currentUsername == null) {
            return "redirect:/login";
        }

        try {
            documentService.deleteDocument(id, currentUsername);
            redirectAttributes.addFlashAttribute("successMessage", "Document was successfully deleted.");
        } catch (IllegalArgumentException ex) {
            redirectAttributes.addFlashAttribute("errorMessage", ex.getMessage());
            return "redirect:/documents/" + id;
        }

        return "redirect:/documents";
    }

    /**
     * Populates the model with safe document view models, permission labels, verified counts,
     * and applies active search / filtering.
     */
    private void populateDashboardModel(
            Model model,
            String username,
            String filter,
            String query,
            String ownerFilter,
            LocalDate fromDate,
            LocalDate toDate) {

        // 1. Retrieve all accessible documents through authorization-enforced service
        List<Document> accessibleDocs = documentService.listAccessibleDocuments(username);

        // 2. Query user's active share permissions to attach accurate permission labels (READ / EDIT)
        Map<Long, SharePermission> userShares = documentShareRepository.findByGranteeUsername(username).stream()
                .collect(Collectors.toMap(
                        s -> s.getDocument().getId(),
                        DocumentShare::getPermission,
                        (p1, p2) -> p1
                ));

        // 3. Transform to safe view models
        List<DocumentItemViewModel> allViewModels = accessibleDocs.stream()
                .map(doc -> {
                    boolean isOwner = doc.getOwner() != null && doc.getOwner().getUsername().equalsIgnoreCase(username);
                    String permLabel = isOwner ? "OWNER" : (userShares.containsKey(doc.getId()) ? userShares.get(doc.getId()).name() : "READ");
                    return DocumentItemViewModel.from(doc, username, permLabel);
                })
                .toList();

        // 4. Calculate real metrics directly from accessible set (before text search filtering)
        long totalCount = allViewModels.size();
        long ownedCount = allViewModels.stream().filter(DocumentItemViewModel::isOwner).count();
        long sharedCount = totalCount - ownedCount;

        // 5. Apply active tab filtering ('all', 'owned', 'shared')
        String activeFilter = (filter != null) ? filter.trim().toLowerCase(Locale.ROOT) : "all";
        List<DocumentItemViewModel> displayedDocuments = allViewModels;
        if ("owned".equals(activeFilter)) {
            displayedDocuments = allViewModels.stream().filter(DocumentItemViewModel::isOwner).toList();
        } else if ("shared".equals(activeFilter)) {
            displayedDocuments = allViewModels.stream().filter(d -> !d.isOwner()).toList();
        } else {
            activeFilter = "all";
        }

        // 6. Apply search and filtering (Keyword/Title, Owner, Date)
        if (query != null && !query.trim().isBlank()) {
            String q = query.trim().toLowerCase(Locale.ROOT);
            displayedDocuments = displayedDocuments.stream()
                    .filter(d -> (d.title() != null && d.title().toLowerCase(Locale.ROOT).contains(q))
                            || (d.description() != null && d.description().toLowerCase(Locale.ROOT).contains(q)))
                    .toList();
        }

        if (ownerFilter != null && !ownerFilter.trim().isBlank()) {
            String o = ownerFilter.trim().toLowerCase(Locale.ROOT);
            displayedDocuments = displayedDocuments.stream()
                    .filter(d -> d.ownerUsername() != null && d.ownerUsername().toLowerCase(Locale.ROOT).contains(o))
                    .toList();
        }

        if (fromDate != null) {
            displayedDocuments = displayedDocuments.stream()
                    .filter(d -> {
                        if (d.createdAt() == null) return false;
                        LocalDate docDate = d.createdAt().atZone(ZoneId.systemDefault()).toLocalDate();
                        return !docDate.isBefore(fromDate);
                    })
                    .toList();
        }

        if (toDate != null) {
            displayedDocuments = displayedDocuments.stream()
                    .filter(d -> {
                        if (d.createdAt() == null) return false;
                        LocalDate docDate = d.createdAt().atZone(ZoneId.systemDefault()).toLocalDate();
                        return !docDate.isAfter(toDate);
                    })
                    .toList();
        }

        model.addAttribute("documents", displayedDocuments);
        model.addAttribute("totalCount", totalCount);
        model.addAttribute("ownedCount", ownedCount);
        model.addAttribute("sharedCount", sharedCount);
        model.addAttribute("activeFilter", activeFilter);
        model.addAttribute("activeTab", activeFilter);
        model.addAttribute("searchQuery", query != null ? query.trim() : "");
        model.addAttribute("ownerFilter", ownerFilter != null ? ownerFilter.trim() : "");
        model.addAttribute("fromDate", fromDate);
        model.addAttribute("toDate", toDate);
        model.addAttribute("pageTitle", "Documents — TrustVault");
    }
}
