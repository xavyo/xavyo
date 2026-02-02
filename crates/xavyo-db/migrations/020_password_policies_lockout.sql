-- Migration: 020_password_policies_lockout.sql
-- Feature: F024 - Password Policies & Account Lockout
-- Description: Create tables for password policies, lockout tracking, and password history

-- ============================================================================
-- Part 1: Extend users table with lockout and password tracking fields
-- ============================================================================

-- Add lockout tracking columns to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS lockout_reason VARCHAR(50);

-- Add password expiration tracking columns to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_expires_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;

-- Backfill password_changed_at for existing users (use created_at as initial value)
UPDATE users SET password_changed_at = created_at WHERE password_changed_at IS NULL;

-- ============================================================================
-- Part 2: Tenant Password Policy table
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_password_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    min_length INTEGER NOT NULL DEFAULT 8,
    max_length INTEGER NOT NULL DEFAULT 128,
    require_uppercase BOOLEAN NOT NULL DEFAULT false,
    require_lowercase BOOLEAN NOT NULL DEFAULT false,
    require_digit BOOLEAN NOT NULL DEFAULT false,
    require_special BOOLEAN NOT NULL DEFAULT false,
    expiration_days INTEGER NOT NULL DEFAULT 0,         -- 0 = never expires
    history_count INTEGER NOT NULL DEFAULT 0,           -- 0 = no history check
    min_age_hours INTEGER NOT NULL DEFAULT 0,           -- 0 = no minimum age
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Validation constraints
    CONSTRAINT chk_min_length CHECK (min_length >= 8 AND min_length <= 128),
    CONSTRAINT chk_max_length CHECK (max_length >= min_length AND max_length <= 128),
    CONSTRAINT chk_expiration_days CHECK (expiration_days >= 0),
    CONSTRAINT chk_history_count CHECK (history_count >= 0 AND history_count <= 24),
    CONSTRAINT chk_min_age_hours CHECK (min_age_hours >= 0)
);

-- ============================================================================
-- Part 3: Tenant Lockout Policy table
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_lockout_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    max_failed_attempts INTEGER NOT NULL DEFAULT 5,     -- 0 = disabled
    lockout_duration_minutes INTEGER NOT NULL DEFAULT 30, -- 0 = permanent until admin unlock
    notify_on_lockout BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Validation constraints
    CONSTRAINT chk_max_failed_attempts CHECK (max_failed_attempts >= 0),
    CONSTRAINT chk_lockout_duration CHECK (lockout_duration_minutes >= 0)
);

-- ============================================================================
-- Part 4: Password History table
-- ============================================================================

CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,                -- Argon2id hash
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for password history
CREATE INDEX IF NOT EXISTS idx_password_history_user_tenant
    ON password_history(user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_password_history_created_at
    ON password_history(user_id, created_at DESC);

-- ============================================================================
-- Part 5: Failed Login Attempts audit table
-- ============================================================================

CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,  -- NULL for unknown emails
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),                             -- IPv4 or IPv6
    failure_reason VARCHAR(50) NOT NULL,                -- invalid_password, account_locked, account_inactive, etc.
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for failed login attempts
CREATE INDEX IF NOT EXISTS idx_failed_login_tenant_time
    ON failed_login_attempts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_failed_login_email_time
    ON failed_login_attempts(email, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_failed_login_ip_time
    ON failed_login_attempts(ip_address, created_at DESC)
    WHERE ip_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_failed_login_user_time
    ON failed_login_attempts(user_id, created_at DESC)
    WHERE user_id IS NOT NULL;

-- ============================================================================
-- Part 6: Row Level Security
-- ============================================================================

-- Enable RLS on new tables
ALTER TABLE tenant_password_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_lockout_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE failed_login_attempts ENABLE ROW LEVEL SECURITY;

-- RLS for tenant_password_policies
DROP POLICY IF EXISTS tenant_isolation_password_policy_select ON tenant_password_policies;
CREATE POLICY tenant_isolation_password_policy_select ON tenant_password_policies
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_password_policy_insert ON tenant_password_policies;
CREATE POLICY tenant_isolation_password_policy_insert ON tenant_password_policies
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_password_policy_update ON tenant_password_policies;
CREATE POLICY tenant_isolation_password_policy_update ON tenant_password_policies
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for tenant_lockout_policies
DROP POLICY IF EXISTS tenant_isolation_lockout_policy_select ON tenant_lockout_policies;
CREATE POLICY tenant_isolation_lockout_policy_select ON tenant_lockout_policies
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_lockout_policy_insert ON tenant_lockout_policies;
CREATE POLICY tenant_isolation_lockout_policy_insert ON tenant_lockout_policies
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_lockout_policy_update ON tenant_lockout_policies;
CREATE POLICY tenant_isolation_lockout_policy_update ON tenant_lockout_policies
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for password_history
DROP POLICY IF EXISTS tenant_isolation_password_history_select ON password_history;
CREATE POLICY tenant_isolation_password_history_select ON password_history
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_password_history_insert ON password_history;
CREATE POLICY tenant_isolation_password_history_insert ON password_history
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_password_history_delete ON password_history;
CREATE POLICY tenant_isolation_password_history_delete ON password_history
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for failed_login_attempts
DROP POLICY IF EXISTS tenant_isolation_failed_login_select ON failed_login_attempts;
CREATE POLICY tenant_isolation_failed_login_select ON failed_login_attempts
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_failed_login_insert ON failed_login_attempts;
CREATE POLICY tenant_isolation_failed_login_insert ON failed_login_attempts
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 7: Triggers for updated_at
-- ============================================================================

-- Trigger for tenant_password_policies
CREATE OR REPLACE FUNCTION update_tenant_password_policies_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_tenant_password_policies_updated_at ON tenant_password_policies;
CREATE TRIGGER trigger_update_tenant_password_policies_updated_at
    BEFORE UPDATE ON tenant_password_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_password_policies_updated_at();

-- Trigger for tenant_lockout_policies
CREATE OR REPLACE FUNCTION update_tenant_lockout_policies_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_tenant_lockout_policies_updated_at ON tenant_lockout_policies;
CREATE TRIGGER trigger_update_tenant_lockout_policies_updated_at
    BEFORE UPDATE ON tenant_lockout_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_lockout_policies_updated_at();

-- ============================================================================
-- Part 8: Comments for documentation
-- ============================================================================

-- User lockout fields
COMMENT ON COLUMN users.failed_login_count IS 'Current count of consecutive failed login attempts';
COMMENT ON COLUMN users.last_failed_login_at IS 'Timestamp of most recent failed login attempt';
COMMENT ON COLUMN users.locked_at IS 'Timestamp when account was locked (NULL if not locked)';
COMMENT ON COLUMN users.locked_until IS 'Timestamp when lockout expires (NULL for permanent lockout)';
COMMENT ON COLUMN users.lockout_reason IS 'Why account was locked: max_attempts, admin_action, security';

-- User password fields
COMMENT ON COLUMN users.password_changed_at IS 'Timestamp of most recent password change';
COMMENT ON COLUMN users.password_expires_at IS 'Timestamp when current password expires (NULL if no expiration)';
COMMENT ON COLUMN users.must_change_password IS 'Admin-forced password change required on next login';

-- Tables
COMMENT ON TABLE tenant_password_policies IS 'Per-tenant password strength and expiration rules';
COMMENT ON TABLE tenant_lockout_policies IS 'Per-tenant account lockout configuration';
COMMENT ON TABLE password_history IS 'User password history for preventing reuse';
COMMENT ON TABLE failed_login_attempts IS 'Audit log of failed login attempts';

-- Password policy columns
COMMENT ON COLUMN tenant_password_policies.min_length IS 'Minimum password length (8-128, default 8)';
COMMENT ON COLUMN tenant_password_policies.max_length IS 'Maximum password length (default 128)';
COMMENT ON COLUMN tenant_password_policies.expiration_days IS 'Days until password expires (0 = never)';
COMMENT ON COLUMN tenant_password_policies.history_count IS 'Number of previous passwords to check (0-24, 0 = no check)';
COMMENT ON COLUMN tenant_password_policies.min_age_hours IS 'Minimum hours before password can be changed (0 = immediate)';

-- Lockout policy columns
COMMENT ON COLUMN tenant_lockout_policies.max_failed_attempts IS 'Failed attempts before lockout (0 = disabled)';
COMMENT ON COLUMN tenant_lockout_policies.lockout_duration_minutes IS 'Lockout duration in minutes (0 = permanent until admin unlock)';
COMMENT ON COLUMN tenant_lockout_policies.notify_on_lockout IS 'Send email notification when account is locked';

-- Failed login attempts columns
COMMENT ON COLUMN failed_login_attempts.failure_reason IS 'Reason for failure: invalid_password, account_locked, account_inactive, unknown_email';
