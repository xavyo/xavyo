-- NHI User Permissions (Feature 204)
-- Grants users explicit access to specific NHI identities.
-- Permission types: 'use' (read), 'manage' (read+write+lifecycle), 'admin' (full+grant)

CREATE TABLE IF NOT EXISTS nhi_user_permissions (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    user_id         UUID        NOT NULL,
    nhi_id          UUID        NOT NULL,
    permission_type TEXT        NOT NULL DEFAULT 'use',
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by      UUID,
    expires_at      TIMESTAMPTZ,

    CONSTRAINT nhi_user_permissions_pkey PRIMARY KEY (id),
    CONSTRAINT nhi_user_permissions_unique UNIQUE (tenant_id, user_id, nhi_id, permission_type),
    CONSTRAINT nhi_user_permissions_type_check CHECK (permission_type IN ('use', 'manage', 'admin')),

    CONSTRAINT nhi_user_permissions_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT nhi_user_permissions_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT nhi_user_permissions_nhi_fk
        FOREIGN KEY (nhi_id) REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_user_permissions_granted_by_fk
        FOREIGN KEY (granted_by) REFERENCES users(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_nhi_user_perms_user
    ON nhi_user_permissions (tenant_id, user_id);

CREATE INDEX IF NOT EXISTS idx_nhi_user_perms_nhi
    ON nhi_user_permissions (tenant_id, nhi_id);

CREATE INDEX IF NOT EXISTS idx_nhi_user_perms_expiry
    ON nhi_user_permissions (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;

-- Row-Level Security
ALTER TABLE nhi_user_permissions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nhi_user_permissions_tenant_isolation ON nhi_user_permissions;
CREATE POLICY nhi_user_permissions_tenant_isolation ON nhi_user_permissions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_user_permissions TO xavyo_app;
