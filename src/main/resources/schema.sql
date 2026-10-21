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
    CONSTRAINT fk_documents_owner FOREIGN KEY (owner_id) REFERENCES app_users(id) ON DELETE RESTRICT
);

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
