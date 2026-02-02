-- Migration: 012_create_social_connections
-- Description: Create social_connections table for storing user social provider links

CREATE TABLE social_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    display_name VARCHAR(255),
    access_token_encrypted BYTEA,
    refresh_token_encrypted BYTEA,
    token_expires_at TIMESTAMPTZ,
    is_private_email BOOLEAN DEFAULT FALSE,
    raw_claims JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One provider account per tenant (can't link same social account to multiple users)
    CONSTRAINT uq_social_connection_provider UNIQUE (tenant_id, provider, provider_user_id),
    -- One connection per provider per user
    CONSTRAINT uq_social_connection_user_provider UNIQUE (tenant_id, user_id, provider)
);

-- Index for finding all connections for a user
CREATE INDEX idx_social_connections_user ON social_connections(tenant_id, user_id);

-- Index for finding connection by email during account linking
CREATE INDEX idx_social_connections_email ON social_connections(tenant_id, provider, email);

-- Enable Row-Level Security
ALTER TABLE social_connections ENABLE ROW LEVEL SECURITY;

-- RLS Policy for tenant isolation
CREATE POLICY tenant_isolation ON social_connections
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Trigger for updated_at
CREATE TRIGGER set_updated_at_social_connections
    BEFORE UPDATE ON social_connections
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
