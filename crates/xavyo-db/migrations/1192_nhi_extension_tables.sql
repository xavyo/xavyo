-- Migration 1192: Create NHI extension tables (tools, agents, service_accounts)
-- Part of 201-tool-nhi-promotion: type-specific fields in 1:1 extension tables.
-- NO RLS on extension tables — always queried via JOIN with nhi_identities.

-- 1. nhi_tools — tool-specific fields
CREATE TABLE IF NOT EXISTS nhi_tools (
    nhi_id           UUID         NOT NULL,
    category         VARCHAR(100),
    input_schema     JSONB        NOT NULL DEFAULT '{}',
    output_schema    JSONB,
    requires_approval BOOLEAN     NOT NULL DEFAULT false,
    max_calls_per_hour INTEGER,
    provider         VARCHAR(255),
    provider_verified BOOLEAN     NOT NULL DEFAULT false,
    checksum         VARCHAR(64),

    CONSTRAINT nhi_tools_pkey PRIMARY KEY (nhi_id),
    CONSTRAINT nhi_tools_identity_fk FOREIGN KEY (nhi_id)
        REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_tools_max_calls_check CHECK (
        max_calls_per_hour IS NULL OR max_calls_per_hour > 0
    )
);

-- 2. nhi_agents — agent-specific fields
CREATE TABLE IF NOT EXISTS nhi_agents (
    nhi_id                   UUID         NOT NULL,
    agent_type               VARCHAR(50)  NOT NULL,
    model_provider           VARCHAR(100),
    model_name               VARCHAR(100),
    model_version            VARCHAR(50),
    agent_card_url           VARCHAR(500),
    agent_card_signature     TEXT,
    max_token_lifetime_secs  INTEGER      NOT NULL DEFAULT 900,
    requires_human_approval  BOOLEAN      NOT NULL DEFAULT false,
    team_id                  UUID         REFERENCES groups(id) ON DELETE SET NULL,

    CONSTRAINT nhi_agents_pkey PRIMARY KEY (nhi_id),
    CONSTRAINT nhi_agents_identity_fk FOREIGN KEY (nhi_id)
        REFERENCES nhi_identities(id) ON DELETE CASCADE,
    CONSTRAINT nhi_agents_type_check CHECK (
        agent_type IN ('autonomous', 'copilot', 'workflow', 'orchestrator')
    ),
    CONSTRAINT nhi_agents_token_lifetime_check CHECK (
        max_token_lifetime_secs > 0 AND max_token_lifetime_secs <= 86400
    )
);

-- 3. nhi_service_accounts — service account-specific fields
CREATE TABLE IF NOT EXISTS nhi_service_accounts (
    nhi_id      UUID NOT NULL,
    purpose     TEXT NOT NULL,
    environment VARCHAR(50),

    CONSTRAINT nhi_service_accounts_pkey PRIMARY KEY (nhi_id),
    CONSTRAINT nhi_service_accounts_identity_fk FOREIGN KEY (nhi_id)
        REFERENCES nhi_identities(id) ON DELETE CASCADE
);

-- Grant permissions to application role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xavyo_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_tools TO xavyo_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_agents TO xavyo_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_service_accounts TO xavyo_app;
    END IF;
END $$;
