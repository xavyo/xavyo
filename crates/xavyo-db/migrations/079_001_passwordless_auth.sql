-- F079: Passwordless Authentication
-- Creates tables for magic link tokens, email OTP codes, and tenant passwordless policies.

-- =============================================================================
-- Table: passwordless_tokens
-- Stores magic link tokens and email OTP codes with shared structure.
-- =============================================================================
CREATE TABLE IF NOT EXISTS passwordless_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    token_type VARCHAR(20) NOT NULL,
    otp_code_hash VARCHAR(64),
    otp_attempts_remaining INT,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT passwordless_tokens_token_hash_unique UNIQUE (token_hash),
    CONSTRAINT passwordless_tokens_token_type_check CHECK (token_type IN ('magic_link', 'email_otp')),
    CONSTRAINT passwordless_tokens_otp_attempts_check CHECK (otp_attempts_remaining IS NULL OR otp_attempts_remaining >= 0)
);

-- Indexes
CREATE INDEX idx_passwordless_tokens_token_hash ON passwordless_tokens (token_hash);
CREATE INDEX idx_passwordless_tokens_user_type ON passwordless_tokens (user_id, token_type);
CREATE INDEX idx_passwordless_tokens_tenant_id ON passwordless_tokens (tenant_id);
CREATE INDEX idx_passwordless_tokens_expires_unused ON passwordless_tokens (expires_at) WHERE used_at IS NULL;

-- Row-Level Security
ALTER TABLE passwordless_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY passwordless_tokens_tenant_isolation ON passwordless_tokens
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- =============================================================================
-- Table: passwordless_policies
-- Per-tenant configuration for passwordless authentication methods.
-- =============================================================================
CREATE TABLE IF NOT EXISTS passwordless_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enabled_methods VARCHAR(50) NOT NULL DEFAULT 'all_methods',
    magic_link_expiry_minutes INT NOT NULL DEFAULT 15,
    otp_expiry_minutes INT NOT NULL DEFAULT 10,
    otp_max_attempts INT NOT NULL DEFAULT 5,
    require_mfa_after_passwordless BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT passwordless_policies_tenant_unique UNIQUE (tenant_id),
    CONSTRAINT passwordless_policies_methods_check CHECK (enabled_methods IN ('disabled', 'magic_link_only', 'otp_only', 'all_methods')),
    CONSTRAINT passwordless_policies_ml_expiry_check CHECK (magic_link_expiry_minutes > 0),
    CONSTRAINT passwordless_policies_otp_expiry_check CHECK (otp_expiry_minutes > 0),
    CONSTRAINT passwordless_policies_otp_attempts_check CHECK (otp_max_attempts > 0)
);

-- Row-Level Security
ALTER TABLE passwordless_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY passwordless_policies_tenant_isolation ON passwordless_policies
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
