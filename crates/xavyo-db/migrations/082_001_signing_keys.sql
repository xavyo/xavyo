-- F082: Security Hardening — signing_keys table
-- Stores JWT signing key pairs for runtime key rotation.
-- Keys have lifecycle states: active, retiring, revoked.

CREATE TABLE IF NOT EXISTS signing_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid         TEXT NOT NULL,
    algorithm   TEXT NOT NULL DEFAULT 'RS256',
    private_key_pem TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'active'
                CHECK (state IN ('active', 'retiring', 'revoked')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Unique key ID across all tenants
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_kid
    ON signing_keys (kid);

-- Fast lookup of active/retiring keys per tenant
CREATE INDEX IF NOT EXISTS idx_signing_keys_tenant_state
    ON signing_keys (tenant_id, state);

-- Row-Level Security
ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY signing_keys_tenant_isolation ON signing_keys
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
