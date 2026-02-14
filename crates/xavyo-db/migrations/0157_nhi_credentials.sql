-- Migration 1193: Create nhi_credentials table
-- Part of 201-tool-nhi-promotion: unified credential storage for all NHI types.
-- Replaces gov_nhi_credentials with proper FK to nhi_identities (no polymorphic trigger).

CREATE TABLE IF NOT EXISTS nhi_credentials (
    id              UUID         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID         NOT NULL,
    nhi_id          UUID         NOT NULL,
    credential_type VARCHAR(50)  NOT NULL,
    credential_hash VARCHAR(255) NOT NULL,
    valid_from      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    valid_until     TIMESTAMPTZ  NOT NULL,
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    rotated_by      UUID,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT nhi_credentials_pkey PRIMARY KEY (id),

    -- Type check
    CONSTRAINT nhi_credentials_type_check CHECK (
        credential_type IN ('api_key', 'secret', 'certificate')
    ),
    -- Validity window
    CONSTRAINT nhi_credentials_validity_check CHECK (
        valid_until > valid_from
    ),

    -- Foreign keys
    CONSTRAINT nhi_credentials_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT nhi_credentials_nhi_fk FOREIGN KEY (nhi_id)
        REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_credentials_rotated_by_fk FOREIGN KEY (rotated_by)
        REFERENCES users(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_nhi_credentials_nhi
    ON nhi_credentials (tenant_id, nhi_id);

CREATE INDEX IF NOT EXISTS idx_nhi_credentials_active
    ON nhi_credentials (tenant_id, nhi_id, is_active)
    WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_nhi_credentials_expiry
    ON nhi_credentials (tenant_id, valid_until)
    WHERE is_active = true;

-- Enable RLS (has its own tenant_id)
ALTER TABLE nhi_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE nhi_credentials FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nhi_credentials_tenant_isolation ON nhi_credentials;
CREATE POLICY nhi_credentials_tenant_isolation ON nhi_credentials
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Grant permissions to application role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xavyo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_credentials TO xavyo_app;
    END IF;
END $$;
