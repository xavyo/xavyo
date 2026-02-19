-- NHI Credential Vault: encrypted secrets with lease-based access
-- Part of WS2: NHI + AgentGateway Integration

-- Encrypted secrets bound to NHI identities
CREATE TABLE IF NOT EXISTS nhi_vaulted_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    nhi_id UUID NOT NULL REFERENCES nhi_identities(id) ON DELETE CASCADE,

    -- Secret metadata (NOT encrypted)
    name TEXT NOT NULL,
    secret_type TEXT NOT NULL DEFAULT 'opaque',
    description TEXT,

    -- Encrypted secret value (AES-256-GCM)
    encrypted_value BYTEA NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    encryption_key_id TEXT NOT NULL,

    -- Injection config: how ext-authz injects this into outbound requests
    inject_as TEXT,
    inject_format TEXT DEFAULT 'raw',

    -- Lifecycle
    expires_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    rotation_interval_days INT,
    max_lease_duration_secs INT NOT NULL DEFAULT 3600,
    max_concurrent_leases INT NOT NULL DEFAULT 5,

    -- Audit
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT nhi_vault_name_unique UNIQUE(tenant_id, nhi_id, name)
);

-- Time-bounded access grants (leases)
CREATE TABLE IF NOT EXISTS nhi_secret_leases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    secret_id UUID NOT NULL REFERENCES nhi_vaulted_secrets(id) ON DELETE CASCADE,

    -- Who holds the lease
    lessee_nhi_id UUID NOT NULL REFERENCES nhi_identities(id),
    lessee_type TEXT NOT NULL,

    -- Lease timing
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    renewed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    -- Status
    status TEXT NOT NULL DEFAULT 'active',
    revocation_reason TEXT,

    -- Audit
    issued_by UUID REFERENCES users(id),
    source_ip INET
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_vault_secrets_nhi ON nhi_vaulted_secrets(tenant_id, nhi_id);
CREATE INDEX IF NOT EXISTS idx_vault_leases_active ON nhi_secret_leases(tenant_id, status, expires_at)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_vault_leases_secret ON nhi_secret_leases(secret_id, status);
CREATE INDEX IF NOT EXISTS idx_vault_leases_lessee ON nhi_secret_leases(lessee_nhi_id, status);

-- RLS policies
ALTER TABLE nhi_vaulted_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE nhi_secret_leases ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nhi_vaulted_secrets_tenant_policy ON nhi_vaulted_secrets;
CREATE POLICY nhi_vaulted_secrets_tenant_policy ON nhi_vaulted_secrets
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS nhi_secret_leases_tenant_policy ON nhi_secret_leases;
CREATE POLICY nhi_secret_leases_tenant_policy ON nhi_secret_leases
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
