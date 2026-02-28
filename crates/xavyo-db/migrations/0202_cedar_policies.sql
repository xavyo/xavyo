-- Cedar policy storage for fine-grained agent authorization.
--
-- Cedar policies are stored as text and compiled at load time.
-- Each policy belongs to a tenant and can optionally target a
-- specific resource type or agent type.

CREATE TABLE IF NOT EXISTS cedar_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Human-readable name for this policy set.
    name VARCHAR(255) NOT NULL,

    -- Optional description.
    description TEXT,

    -- Cedar policy text (one or more Cedar policy statements).
    policy_text TEXT NOT NULL,

    -- Optional Cedar schema text for validation.
    schema_text TEXT,

    -- Scope filters (optional, for selective loading).
    -- If set, this policy only applies to specific resource types or agent types.
    resource_type VARCHAR(100),
    agent_type VARCHAR(100),

    -- Priority for ordering (lower = higher precedence, consistent with existing policies).
    priority INTEGER NOT NULL DEFAULT 100,

    -- Status: active, inactive, draft.
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'inactive', 'draft')),

    -- Audit fields.
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique policy name per tenant.
    CONSTRAINT uq_cedar_policies_tenant_name UNIQUE (tenant_id, name)
);

-- RLS
ALTER TABLE cedar_policies ENABLE ROW LEVEL SECURITY;

-- Indexes for common queries.
CREATE INDEX IF NOT EXISTS idx_cedar_policies_tenant_status
    ON cedar_policies (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_cedar_policies_resource_type
    ON cedar_policies (tenant_id, resource_type)
    WHERE resource_type IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cedar_policies_agent_type
    ON cedar_policies (tenant_id, agent_type)
    WHERE agent_type IS NOT NULL;
