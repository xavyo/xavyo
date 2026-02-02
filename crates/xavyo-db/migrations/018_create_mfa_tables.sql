-- Migration: 018_create_mfa_tables.sql
-- Feature: F022 - MFA TOTP Authentication
-- Description: Create tables for TOTP secrets, recovery codes, and MFA audit logging

-- Add mfa_policy column to tenants table
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS mfa_policy VARCHAR(20) NOT NULL DEFAULT 'optional'
  CHECK (mfa_policy IN ('disabled', 'optional', 'required'));

-- TOTP secrets table (encrypted at rest)
CREATE TABLE IF NOT EXISTS user_totp_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    secret_encrypted BYTEA NOT NULL,        -- AES-256-GCM encrypted TOTP secret
    iv BYTEA NOT NULL,                      -- Initialization vector for AES-GCM
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    setup_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    setup_completed_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT unique_user_totp UNIQUE (user_id)  -- One TOTP secret per user
);

-- Recovery codes table (stored as SHA-256 hashes)
CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL,         -- SHA-256 hash of recovery code
    used_at TIMESTAMPTZ,                    -- NULL if not used, timestamp if consumed
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- MFA audit log table
CREATE TABLE IF NOT EXISTS mfa_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,            -- 'setup_initiated', 'setup_completed', 'verify_success', 'verify_failed', 'disabled', 'recovery_used', 'recovery_regenerated', 'policy_changed'
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB,                         -- Additional context (e.g., failure reason)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_totp_secrets_user_id ON user_totp_secrets(user_id);
CREATE INDEX IF NOT EXISTS idx_user_totp_secrets_tenant_id ON user_totp_secrets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_totp_secrets_is_enabled ON user_totp_secrets(is_enabled) WHERE is_enabled = true;

CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_user_id ON user_recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_tenant_id ON user_recovery_codes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_unused ON user_recovery_codes(user_id) WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_mfa_audit_log_user_id ON mfa_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_log_tenant_id ON mfa_audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_log_created_at ON mfa_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_log_action ON mfa_audit_log(action);

-- Enable Row Level Security
ALTER TABLE user_totp_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_audit_log ENABLE ROW LEVEL SECURITY;

-- RLS Policies for tenant isolation
-- user_totp_secrets policies
DROP POLICY IF EXISTS tenant_isolation_totp_select ON user_totp_secrets;
CREATE POLICY tenant_isolation_totp_select ON user_totp_secrets
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_totp_insert ON user_totp_secrets;
CREATE POLICY tenant_isolation_totp_insert ON user_totp_secrets
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_totp_update ON user_totp_secrets;
CREATE POLICY tenant_isolation_totp_update ON user_totp_secrets
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_totp_delete ON user_totp_secrets;
CREATE POLICY tenant_isolation_totp_delete ON user_totp_secrets
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- user_recovery_codes policies
DROP POLICY IF EXISTS tenant_isolation_recovery_select ON user_recovery_codes;
CREATE POLICY tenant_isolation_recovery_select ON user_recovery_codes
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_recovery_insert ON user_recovery_codes;
CREATE POLICY tenant_isolation_recovery_insert ON user_recovery_codes
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_recovery_update ON user_recovery_codes;
CREATE POLICY tenant_isolation_recovery_update ON user_recovery_codes
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_recovery_delete ON user_recovery_codes;
CREATE POLICY tenant_isolation_recovery_delete ON user_recovery_codes
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- mfa_audit_log policies
DROP POLICY IF EXISTS tenant_isolation_mfa_audit_select ON mfa_audit_log;
CREATE POLICY tenant_isolation_mfa_audit_select ON mfa_audit_log
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_mfa_audit_insert ON mfa_audit_log;
CREATE POLICY tenant_isolation_mfa_audit_insert ON mfa_audit_log
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Trigger for updated_at on user_totp_secrets
CREATE OR REPLACE FUNCTION update_user_totp_secrets_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_user_totp_secrets_updated_at ON user_totp_secrets;
CREATE TRIGGER trigger_update_user_totp_secrets_updated_at
    BEFORE UPDATE ON user_totp_secrets
    FOR EACH ROW
    EXECUTE FUNCTION update_user_totp_secrets_updated_at();

-- Comments for documentation
COMMENT ON TABLE user_totp_secrets IS 'Stores encrypted TOTP secrets for MFA authentication';
COMMENT ON COLUMN user_totp_secrets.secret_encrypted IS 'AES-256-GCM encrypted TOTP secret (160-bit minimum)';
COMMENT ON COLUMN user_totp_secrets.iv IS 'Initialization vector for AES-GCM encryption';
COMMENT ON COLUMN user_totp_secrets.is_enabled IS 'True after user verifies TOTP setup with valid code';
COMMENT ON COLUMN user_totp_secrets.failed_attempts IS 'Consecutive failed TOTP verification attempts';
COMMENT ON COLUMN user_totp_secrets.locked_until IS 'Account locked for TOTP until this timestamp';

COMMENT ON TABLE user_recovery_codes IS 'Stores hashed recovery codes for MFA account recovery';
COMMENT ON COLUMN user_recovery_codes.code_hash IS 'SHA-256 hash of 16-character alphanumeric recovery code';
COMMENT ON COLUMN user_recovery_codes.used_at IS 'NULL if unused, timestamp when consumed';

COMMENT ON TABLE mfa_audit_log IS 'Audit trail for all MFA-related actions';
COMMENT ON COLUMN mfa_audit_log.action IS 'One of: setup_initiated, setup_completed, verify_success, verify_failed, disabled, recovery_used, recovery_regenerated, policy_changed';
COMMENT ON COLUMN tenants.mfa_policy IS 'Tenant MFA policy: disabled (no MFA), optional (user choice), required (mandatory MFA)';
