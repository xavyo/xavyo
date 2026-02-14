-- NHI-to-NHI Permissions (Feature 204)
-- Grants one NHI calling/delegation rights to another NHI.
-- Permission types: 'call' (invoke), 'delegate' (act on behalf of)

CREATE TABLE IF NOT EXISTS nhi_nhi_permissions (
    id                UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL,
    source_nhi_id     UUID        NOT NULL,
    target_nhi_id     UUID        NOT NULL,
    permission_type   TEXT        NOT NULL DEFAULT 'call',
    allowed_actions   JSONB,
    max_calls_per_hour INTEGER,
    granted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by        UUID,
    expires_at        TIMESTAMPTZ,

    CONSTRAINT nhi_nhi_permissions_pkey PRIMARY KEY (id),
    CONSTRAINT nhi_nhi_permissions_unique UNIQUE (tenant_id, source_nhi_id, target_nhi_id, permission_type),
    CONSTRAINT nhi_nhi_permissions_type_check CHECK (permission_type IN ('call', 'delegate')),
    CONSTRAINT nhi_nhi_permissions_no_self CHECK (source_nhi_id <> target_nhi_id),
    CONSTRAINT nhi_nhi_permissions_max_calls_check CHECK (max_calls_per_hour IS NULL OR max_calls_per_hour > 0),

    CONSTRAINT nhi_nhi_permissions_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT nhi_nhi_permissions_source_fk
        FOREIGN KEY (source_nhi_id) REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_nhi_permissions_target_fk
        FOREIGN KEY (target_nhi_id) REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_nhi_permissions_granted_by_fk
        FOREIGN KEY (granted_by) REFERENCES users(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_nhi_nhi_perms_source
    ON nhi_nhi_permissions (tenant_id, source_nhi_id);

CREATE INDEX IF NOT EXISTS idx_nhi_nhi_perms_target
    ON nhi_nhi_permissions (tenant_id, target_nhi_id);

CREATE INDEX IF NOT EXISTS idx_nhi_nhi_perms_expiry
    ON nhi_nhi_permissions (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;

-- Row-Level Security
ALTER TABLE nhi_nhi_permissions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nhi_nhi_permissions_tenant_isolation ON nhi_nhi_permissions;
CREATE POLICY nhi_nhi_permissions_tenant_isolation ON nhi_nhi_permissions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_nhi_permissions TO xavyo_app;
