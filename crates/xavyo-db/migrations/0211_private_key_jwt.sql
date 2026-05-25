-- Migration: private_key_jwt client authentication (RFC 7523 / OIDC §9)
--
-- Two parts:
--  1. oauth_clients.jwks — the client's inline JSON Web Key Set used to verify
--     its client_assertion signatures. NULL ⇒ the client does not use
--     private_key_jwt. (Remote jwks_uri fetch is a follow-up.)
--  2. client_assertion_jtis — replay cache for accepted client-assertion `jti`s,
--     mirroring dpop_proof_jtis. Tenant-scoped; rows vacuumed past expiry.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS jwks JSONB;

COMMENT ON COLUMN oauth_clients.jwks
    IS 'Inline JSON Web Key Set for private_key_jwt client_assertion verification (RFC 7523); NULL = not used';

CREATE TABLE IF NOT EXISTS client_assertion_jtis (
    jti TEXT NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- (tenant_id, jti) uniqueness drives the ON CONFLICT replay check.
    PRIMARY KEY (tenant_id, jti)
);

-- Cleanup index for the vacuum of expired assertion records.
CREATE INDEX IF NOT EXISTS idx_client_assertion_jtis_expires_at
    ON client_assertion_jtis(expires_at);

-- Row-Level Security for tenant isolation.
ALTER TABLE client_assertion_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_assertion_jtis FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON client_assertion_jtis;
CREATE POLICY tenant_isolation_policy ON client_assertion_jtis
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE client_assertion_jtis IS 'private_key_jwt client_assertion jti replay cache (RFC 7523); rows expire after the assertion lifetime window';
