-- ==============================================================================
-- TrustVault Database Schema
-- Compatible with PostgreSQL (Production / Dev)
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. User Accounts Table
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    role VARCHAR(20) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_app_users_username ON app_users(username);
CREATE INDEX IF NOT EXISTS idx_app_users_email ON app_users(email);

-- ------------------------------------------------------------------------------
-- 2. Documents Table
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS documents (
    id BIGSERIAL PRIMARY KEY,
    storage_key UUID NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description VARCHAR(1000),
    owner_id BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    file_original_name VARCHAR(255),
    file_content_type VARCHAR(100),
    file_size BIGINT,
    file_checksum VARCHAR(64),
    file_uploaded_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_documents_owner FOREIGN KEY (owner_id) REFERENCES app_users(id) ON DELETE RESTRICT,
    CONSTRAINT chk_documents_file_size CHECK (file_size IS NULL OR file_size >= 0)
);

-- Idempotent schema evolution for existing PostgreSQL databases initialized before Milestone 2.4 Stage 2:
-- NOTE: In production with ddl-auto: validate, Spring Boot does NOT execute schema.sql automatically on startup.
-- These statements must be executed manually by a database administrator against existing PostgreSQL instances.
ALTER TABLE documents ADD COLUMN IF NOT EXISTS file_original_name VARCHAR(255);
ALTER TABLE documents ADD COLUMN IF NOT EXISTS file_content_type VARCHAR(100);
ALTER TABLE documents ADD COLUMN IF NOT EXISTS file_size BIGINT;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS file_checksum VARCHAR(64);
ALTER TABLE documents ADD COLUMN IF NOT EXISTS file_uploaded_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_documents_owner_id ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_storage_key ON documents(storage_key);

-- ------------------------------------------------------------------------------
-- 3. Document Shares Table
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS document_shares (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT NOT NULL,
    grantee_id BIGINT NOT NULL,
    permission VARCHAR(20) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_shares_document FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_shares_grantee FOREIGN KEY (grantee_id) REFERENCES app_users(id) ON DELETE CASCADE,
    CONSTRAINT uq_document_grantee UNIQUE (document_id, grantee_id)
);

CREATE INDEX IF NOT EXISTS idx_document_shares_grantee_id ON document_shares(grantee_id);
CREATE INDEX IF NOT EXISTS idx_document_shares_document_id ON document_shares(document_id);

-- ------------------------------------------------------------------------------
-- 4. Audit Events Table (Append-Only, Tamper-Resistant)
-- ------------------------------------------------------------------------------
-- Note: document_id is stored as an unconstrained logical reference without a foreign
-- key cascade to ensure that document deletion never alters or purges historical audit records.
-- document_storage_key preserves the immutable UUID of the referenced document.
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_username VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    document_id BIGINT,
    document_storage_key UUID,
    target_username VARCHAR(50),
    outcome VARCHAR(20) NOT NULL,
    client_ip VARCHAR(45),
    details VARCHAR(500)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_username);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_doc_id ON audit_events(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_storage_key ON audit_events(document_storage_key);
CREATE INDEX IF NOT EXISTS idx_audit_events_outcome ON audit_events(outcome);
