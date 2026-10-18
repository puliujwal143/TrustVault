/**
 * Domain Entity Model for TrustVault.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Contains JPA entity classes representing persistent database tables.</li>
 *   <li>Defines table schemas, primary keys, relationships, and constraints.</li>
 *   <li>Includes audit metadata fields (created_at, updated_at, created_by, version).</li>
 *   <li>Never stores file contents directly in database tables; references private storage paths/UUIDs.</li>
 * </ul>
 *
 * <p>Phase 1 establishes package boundaries; schema entities will be mapped in subsequent phases.
 */
package com.trustvault.entity;
