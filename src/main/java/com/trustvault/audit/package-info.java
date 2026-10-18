/**
 * Audit Logging and Security Monitoring for TrustVault.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Records immutable security audit events for enterprise compliance.</li>
 *   <li>Captures principal identity, action verb, target resource ID, IP address, and status.</li>
 *   <li>Logs sensitive operations (authentication, document access, share grants, revocations).</li>
 *   <li>Ensures audit events cannot be bypassed or tampered with by standard application users.</li>
 * </ul>
 *
 * <p>Phase 1 establishes package boundaries; dedicated audit event listeners and storage will be added in Phase 2+.
 */
package com.trustvault.audit;
