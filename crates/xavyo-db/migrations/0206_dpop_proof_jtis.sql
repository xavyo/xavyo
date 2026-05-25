-- Migration: DPoP proof replay cache (RFC 9449 §11.1)
--
-- Stores the `jti` of each accepted DPoP proof for the proof acceptance window
-- (~120s) so a replayed proof is rejected. Rows are short-lived and vacuumed
-- once past `expires_at`. Tenant-scoped per CLAUDE.md §2 — the tenant comes
-- from the access token being presented (or issued), not from the proof.

CREATE TABLE IF NOT EXISTS dpop_proof_jtis (
    jti TEXT NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- (tenant_id, jti) uniqueness drives the ON CONFLICT replay check.
    PRIMARY KEY (tenant_id, jti)
);

-- Cleanup index for the vacuum of expired proof records.
CREATE INDEX IF NOT EXISTS idx_dpop_proof_jtis_expires_at
    ON dpop_proof_jtis(expires_at);

-- Row-Level Security for tenant isolation.
ALTER TABLE dpop_proof_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpop_proof_jtis FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON dpop_proof_jtis;
CREATE POLICY tenant_isolation_policy ON dpop_proof_jtis
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE dpop_proof_jtis IS 'DPoP proof jti replay cache (RFC 9449); rows expire after the proof acceptance window';
