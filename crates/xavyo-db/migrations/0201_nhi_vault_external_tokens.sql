-- External OAuth Provider Token Vault.
--
-- Stores encrypted OAuth tokens from external providers (CRM, Google, Slack, etc.)
-- so agents can act on behalf of users with their provider-scoped credentials.
--
-- Follows Auth0 Token Vault pattern: tokens stored encrypted, auto-refreshed
-- on access, exchange API for agent-to-user-token resolution.

CREATE TABLE IF NOT EXISTS nhi_vault_external_tokens (
    id                        UUID         NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                 UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    nhi_id                    UUID         NOT NULL REFERENCES nhi_identities(id) ON DELETE CASCADE,

    -- Which user authorized this token (the human who delegated)
    user_id                   UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- External provider info
    provider                  VARCHAR(100) NOT NULL,
    provider_client_id        VARCHAR(255),

    -- Encrypted access token (AES-256-GCM)
    encrypted_access_token    BYTEA        NOT NULL,
    access_token_nonce        BYTEA        NOT NULL,
    access_token_key_id       TEXT         NOT NULL,

    -- Encrypted refresh token (optional — not all providers issue refresh tokens)
    encrypted_refresh_token   BYTEA,
    refresh_token_nonce       BYTEA,
    refresh_token_key_id      TEXT,

    -- Token metadata
    token_type                VARCHAR(50)  NOT NULL DEFAULT 'bearer',
    scopes                    TEXT[]       NOT NULL DEFAULT '{}',

    -- Expiry tracking
    access_token_expires_at   TIMESTAMPTZ,
    refresh_token_expires_at  TIMESTAMPTZ,
    last_refreshed_at         TIMESTAMPTZ,

    -- Provider token endpoint (for auto-refresh)
    token_endpoint            VARCHAR(500),

    -- Audit
    created_by                UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT nhi_vault_external_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT nhi_vault_ext_tokens_unique UNIQUE (tenant_id, nhi_id, user_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_vault_ext_tokens_nhi
    ON nhi_vault_external_tokens (tenant_id, nhi_id);
CREATE INDEX IF NOT EXISTS idx_vault_ext_tokens_user
    ON nhi_vault_external_tokens (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_vault_ext_tokens_provider
    ON nhi_vault_external_tokens (tenant_id, provider);

-- Enable RLS (tenant isolation)
ALTER TABLE nhi_vault_external_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY nhi_vault_ext_tokens_tenant_isolation ON nhi_vault_external_tokens
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON nhi_vault_external_tokens TO xavyo_app;
