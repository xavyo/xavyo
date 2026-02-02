-- Migration: 028_create_webauthn_tables.sql
-- Feature: 032-mfa-webauthn
-- Purpose: Add WebAuthn/FIDO2 MFA support tables

-- ============================================================================
-- Table: user_webauthn_credentials
-- Stores registered WebAuthn credentials for users
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    aaguid BYTEA,
    name VARCHAR(100) NOT NULL DEFAULT 'Security Key',
    authenticator_type VARCHAR(20) NOT NULL,
    transports TEXT[],
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure credential_id is unique per tenant (allows same physical key across tenants)
    CONSTRAINT unique_credential_per_tenant UNIQUE (tenant_id, credential_id)
);

-- Index for user credential lookups
CREATE INDEX IF NOT EXISTS idx_webauthn_creds_user_tenant
    ON user_webauthn_credentials(user_id, tenant_id);

-- Index for tenant-based queries
CREATE INDEX IF NOT EXISTS idx_webauthn_creds_tenant
    ON user_webauthn_credentials(tenant_id);

-- ============================================================================
-- Table: webauthn_challenges
-- Temporary storage for WebAuthn ceremony challenges
-- ============================================================================
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    challenge BYTEA NOT NULL,
    ceremony_type VARCHAR(20) NOT NULL,
    state_json JSONB NOT NULL,
    credential_name VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),

    -- Validation
    CONSTRAINT valid_ceremony_type CHECK (ceremony_type IN ('registration', 'authentication'))
);

-- Index for user challenge lookups during ceremony
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user
    ON webauthn_challenges(user_id, ceremony_type);

-- Index for cleanup of expired challenges
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
    ON webauthn_challenges(expires_at);

-- ============================================================================
-- Table: tenant_webauthn_policies
-- Tenant-level WebAuthn configuration
-- ============================================================================
CREATE TABLE IF NOT EXISTS tenant_webauthn_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    webauthn_enabled BOOLEAN NOT NULL DEFAULT true,
    require_attestation BOOLEAN NOT NULL DEFAULT false,
    user_verification VARCHAR(20) NOT NULL DEFAULT 'preferred',
    allowed_authenticator_types TEXT[],
    max_credentials_per_user INTEGER NOT NULL DEFAULT 10,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Validation
    CONSTRAINT valid_user_verification CHECK (
        user_verification IN ('discouraged', 'preferred', 'required')
    ),
    CONSTRAINT valid_max_credentials CHECK (
        max_credentials_per_user >= 1 AND max_credentials_per_user <= 20
    )
);

-- ============================================================================
-- Table: webauthn_audit_log
-- Security audit log for WebAuthn operations
-- ============================================================================
CREATE TABLE IF NOT EXISTS webauthn_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    credential_id UUID REFERENCES user_webauthn_credentials(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Validation for action types
    CONSTRAINT valid_webauthn_action CHECK (
        action IN (
            'registration_started',
            'registration_completed',
            'registration_failed',
            'authentication_started',
            'authentication_success',
            'authentication_failed',
            'credential_renamed',
            'credential_deleted',
            'credential_revoked_by_admin',
            'counter_anomaly_detected'
        )
    )
);

-- Index for user audit lookups
CREATE INDEX IF NOT EXISTS idx_webauthn_audit_user_tenant
    ON webauthn_audit_log(user_id, tenant_id);

-- Index for chronological queries
CREATE INDEX IF NOT EXISTS idx_webauthn_audit_created
    ON webauthn_audit_log(created_at DESC);

-- Index for action-based queries
CREATE INDEX IF NOT EXISTS idx_webauthn_audit_action
    ON webauthn_audit_log(action);

-- ============================================================================
-- Row-Level Security (RLS)
-- ============================================================================

-- Enable RLS on all WebAuthn tables
ALTER TABLE user_webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_webauthn_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_audit_log ENABLE ROW LEVEL SECURITY;

-- RLS Policies for tenant isolation
CREATE POLICY tenant_isolation_webauthn_creds ON user_webauthn_credentials
    FOR ALL
    USING (tenant_id = COALESCE(
        NULLIF(current_setting('app.current_tenant', true), '')::uuid,
        tenant_id
    ));

CREATE POLICY tenant_isolation_webauthn_challenges ON webauthn_challenges
    FOR ALL
    USING (tenant_id = COALESCE(
        NULLIF(current_setting('app.current_tenant', true), '')::uuid,
        tenant_id
    ));

CREATE POLICY tenant_isolation_webauthn_policies ON tenant_webauthn_policies
    FOR ALL
    USING (tenant_id = COALESCE(
        NULLIF(current_setting('app.current_tenant', true), '')::uuid,
        tenant_id
    ));

CREATE POLICY tenant_isolation_webauthn_audit ON webauthn_audit_log
    FOR ALL
    USING (tenant_id = COALESCE(
        NULLIF(current_setting('app.current_tenant', true), '')::uuid,
        tenant_id
    ));

-- ============================================================================
-- Trigger for updated_at timestamp
-- ============================================================================
CREATE OR REPLACE FUNCTION update_webauthn_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_webauthn_creds_updated_at
    BEFORE UPDATE ON user_webauthn_credentials
    FOR EACH ROW
    EXECUTE FUNCTION update_webauthn_updated_at();

CREATE TRIGGER trigger_webauthn_policy_updated_at
    BEFORE UPDATE ON tenant_webauthn_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_webauthn_updated_at();

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE user_webauthn_credentials IS 'Stores WebAuthn/FIDO2 credentials registered by users for MFA';
COMMENT ON TABLE webauthn_challenges IS 'Temporary storage for WebAuthn ceremony challenges (5-minute TTL)';
COMMENT ON TABLE tenant_webauthn_policies IS 'Per-tenant WebAuthn configuration and policy settings';
COMMENT ON TABLE webauthn_audit_log IS 'Audit trail for all WebAuthn operations';

COMMENT ON COLUMN user_webauthn_credentials.credential_id IS 'Authenticator-generated credential ID (base64url decoded)';
COMMENT ON COLUMN user_webauthn_credentials.public_key IS 'COSE-encoded public key';
COMMENT ON COLUMN user_webauthn_credentials.sign_count IS 'Counter for clone detection';
COMMENT ON COLUMN user_webauthn_credentials.aaguid IS 'Authenticator Attestation GUID (16 bytes)';
COMMENT ON COLUMN user_webauthn_credentials.authenticator_type IS 'platform or cross-platform';
COMMENT ON COLUMN user_webauthn_credentials.transports IS 'Supported transports: usb, nfc, ble, internal, hybrid';
COMMENT ON COLUMN user_webauthn_credentials.backup_eligible IS 'Whether credential supports backup (passkey sync)';
COMMENT ON COLUMN user_webauthn_credentials.backup_state IS 'Whether credential is currently backed up';

COMMENT ON COLUMN webauthn_challenges.state_json IS 'Serialized webauthn-rs PasskeyRegistration or PasskeyAuthentication state';
COMMENT ON COLUMN webauthn_challenges.credential_name IS 'User-provided name for the credential (registration only)';

COMMENT ON COLUMN tenant_webauthn_policies.user_verification IS 'discouraged, preferred, or required';
COMMENT ON COLUMN tenant_webauthn_policies.allowed_authenticator_types IS 'NULL=all, or array of: platform, cross-platform';
