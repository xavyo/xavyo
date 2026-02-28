-- Agent Blueprints: reusable templates for agent provisioning.
-- A blueprint captures the "recipe" for creating agents (model config,
-- default permissions, delegation defaults) so organisations can stamp out
-- agents consistently.

CREATE TABLE IF NOT EXISTS nhi_agent_blueprints (
    id                       UUID         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                     VARCHAR(255) NOT NULL,
    description              TEXT,

    -- Agent configuration template
    agent_type               VARCHAR(50)  NOT NULL DEFAULT 'autonomous',
    model_provider           VARCHAR(100),
    model_name               VARCHAR(100),
    model_version            VARCHAR(50),

    -- Defaults applied when provisioning from this blueprint
    max_token_lifetime_secs  INTEGER      NOT NULL DEFAULT 900,
    requires_human_approval  BOOLEAN      NOT NULL DEFAULT false,

    -- Default entitlements assigned to agents created from this blueprint
    default_entitlements     TEXT[]       NOT NULL DEFAULT '{}',

    -- Default delegation configuration (JSONB for flexibility)
    default_delegation       JSONB,

    -- Organisation & metadata
    tags                     TEXT[]       NOT NULL DEFAULT '{}',
    created_by               UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT nhi_agent_blueprints_pkey PRIMARY KEY (id),
    CONSTRAINT nhi_agent_blueprints_tenant_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT nhi_agent_blueprints_type_check CHECK (
        agent_type IN ('autonomous', 'copilot', 'workflow', 'orchestrator')
    ),
    CONSTRAINT nhi_agent_blueprints_token_lifetime_check CHECK (
        max_token_lifetime_secs > 0 AND max_token_lifetime_secs <= 86400
    )
);

CREATE INDEX IF NOT EXISTS idx_nhi_agent_blueprints_tenant
    ON nhi_agent_blueprints (tenant_id);
CREATE INDEX IF NOT EXISTS idx_nhi_agent_blueprints_created_by
    ON nhi_agent_blueprints (created_by);
CREATE INDEX IF NOT EXISTS idx_nhi_agent_blueprints_tags
    ON nhi_agent_blueprints USING gin (tags);

-- Enable RLS (tenant isolation)
ALTER TABLE nhi_agent_blueprints ENABLE ROW LEVEL SECURITY;

CREATE POLICY nhi_agent_blueprints_tenant_isolation ON nhi_agent_blueprints
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_agent_blueprints TO xavyo_app;
