-- Migration 1194: Create nhi_tool_permissions table
-- Part of 201-tool-nhi-promotion: agent-to-tool permission grants.
-- Replaces ai_agent_tool_permissions with proper FK to nhi_identities.

CREATE TABLE IF NOT EXISTS nhi_tool_permissions (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    agent_nhi_id    UUID        NOT NULL,
    tool_nhi_id     UUID        NOT NULL,
    allowed_parameters JSONB,
    max_calls_per_hour INTEGER,
    requires_approval  BOOLEAN,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by      UUID,
    expires_at      TIMESTAMPTZ,

    CONSTRAINT nhi_tool_permissions_pkey PRIMARY KEY (id),

    -- One permission per agent-tool pair per tenant
    CONSTRAINT nhi_tool_permissions_unique UNIQUE (tenant_id, agent_nhi_id, tool_nhi_id),

    -- Rate limit must be positive
    CONSTRAINT nhi_tool_permissions_max_calls_check CHECK (
        max_calls_per_hour IS NULL OR max_calls_per_hour > 0
    ),

    -- Foreign keys
    CONSTRAINT nhi_tool_permissions_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT nhi_tool_permissions_agent_fk FOREIGN KEY (agent_nhi_id)
        REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_tool_permissions_tool_fk FOREIGN KEY (tool_nhi_id)
        REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_tool_permissions_granted_by_fk FOREIGN KEY (granted_by)
        REFERENCES users(id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_nhi_tool_perms_agent
    ON nhi_tool_permissions (tenant_id, agent_nhi_id);

CREATE INDEX IF NOT EXISTS idx_nhi_tool_perms_tool
    ON nhi_tool_permissions (tenant_id, tool_nhi_id);

CREATE INDEX IF NOT EXISTS idx_nhi_tool_perms_expiry
    ON nhi_tool_permissions (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;

-- Enable RLS (has its own tenant_id)
ALTER TABLE nhi_tool_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE nhi_tool_permissions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nhi_tool_permissions_tenant_isolation ON nhi_tool_permissions;
CREATE POLICY nhi_tool_permissions_tenant_isolation ON nhi_tool_permissions
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Grant permissions to application role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xavyo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_tool_permissions TO xavyo_app;
    END IF;
END $$;
