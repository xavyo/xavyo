-- Migration: SAML AuthnRequest Session Storage
-- Purpose: Store AuthnRequest IDs to prevent replay attacks
-- Feature: F-038 SAML Session Security

CREATE TABLE IF NOT EXISTS saml_authn_request_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id VARCHAR(256) NOT NULL,
    sp_entity_id VARCHAR(512) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    relay_state TEXT,

    -- Ensure unique request IDs per tenant
    UNIQUE(tenant_id, request_id)
);

-- Index for fast lookups by tenant and request ID
CREATE INDEX IF NOT EXISTS idx_saml_sessions_tenant_request
    ON saml_authn_request_sessions(tenant_id, request_id);

-- Index for cleanup of expired sessions
CREATE INDEX IF NOT EXISTS idx_saml_sessions_expires
    ON saml_authn_request_sessions(expires_at)
    WHERE consumed_at IS NULL;

-- Enable Row-Level Security for tenant isolation
ALTER TABLE saml_authn_request_sessions ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Tenants can only access their own sessions
CREATE POLICY tenant_isolation_saml_sessions ON saml_authn_request_sessions
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE saml_authn_request_sessions IS 'Stores SAML AuthnRequest IDs for replay attack prevention';
COMMENT ON COLUMN saml_authn_request_sessions.request_id IS 'The SAML AuthnRequest ID from the SP';
COMMENT ON COLUMN saml_authn_request_sessions.consumed_at IS 'When this request was used - NULL means unused';
