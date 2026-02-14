-- Migration: 019_create_session_tables.sql
-- Feature: F023 - Session Management
-- Description: Create tables for session tracking and tenant session policies

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    refresh_token_id UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    device_id VARCHAR(64),                    -- Device fingerprint (optional)
    device_name VARCHAR(255),                 -- e.g., "Chrome on MacOS"
    device_type VARCHAR(50),                  -- 'desktop', 'mobile', 'tablet', 'unknown'
    browser VARCHAR(100),
    browser_version VARCHAR(50),
    os VARCHAR(100),
    os_version VARCHAR(50),
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(100)               -- 'user_logout', 'admin_revoke', 'max_sessions', 'idle_timeout', 'password_change', 'security'
);

-- Tenant session policies table
CREATE TABLE IF NOT EXISTS tenant_session_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    access_token_ttl_minutes INTEGER NOT NULL DEFAULT 15,
    refresh_token_ttl_days INTEGER NOT NULL DEFAULT 7,
    idle_timeout_minutes INTEGER NOT NULL DEFAULT 30,        -- 0 = disabled
    absolute_timeout_hours INTEGER NOT NULL DEFAULT 24,
    max_concurrent_sessions INTEGER NOT NULL DEFAULT 0,      -- 0 = unlimited
    track_device_info BOOLEAN NOT NULL DEFAULT true,
    remember_me_ttl_days INTEGER NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_id ON sessions(refresh_token_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)
    WHERE revoked_at IS NULL;

-- Enable Row Level Security
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_session_policies ENABLE ROW LEVEL SECURITY;

-- RLS Policies for sessions
DROP POLICY IF EXISTS tenant_isolation_sessions_select ON sessions;
CREATE POLICY tenant_isolation_sessions_select ON sessions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_sessions_insert ON sessions;
CREATE POLICY tenant_isolation_sessions_insert ON sessions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_sessions_update ON sessions;
CREATE POLICY tenant_isolation_sessions_update ON sessions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_sessions_delete ON sessions;
CREATE POLICY tenant_isolation_sessions_delete ON sessions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS Policies for tenant_session_policies
DROP POLICY IF EXISTS tenant_isolation_policies_select ON tenant_session_policies;
CREATE POLICY tenant_isolation_policies_select ON tenant_session_policies
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_policies_insert ON tenant_session_policies;
CREATE POLICY tenant_isolation_policies_insert ON tenant_session_policies
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_policies_update ON tenant_session_policies;
CREATE POLICY tenant_isolation_policies_update ON tenant_session_policies
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Trigger for updated_at on tenant_session_policies
CREATE OR REPLACE FUNCTION update_tenant_session_policies_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_tenant_session_policies_updated_at ON tenant_session_policies;
CREATE TRIGGER trigger_update_tenant_session_policies_updated_at
    BEFORE UPDATE ON tenant_session_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_session_policies_updated_at();

-- Comments for documentation
COMMENT ON TABLE sessions IS 'Tracks active user sessions with device information';
COMMENT ON COLUMN sessions.device_id IS 'Optional device fingerprint for identification';
COMMENT ON COLUMN sessions.device_name IS 'Human-readable device name (e.g., Chrome on MacOS)';
COMMENT ON COLUMN sessions.device_type IS 'Device category: desktop, mobile, tablet, unknown';
COMMENT ON COLUMN sessions.revoked_reason IS 'Why session was revoked: user_logout, admin_revoke, max_sessions, idle_timeout, password_change, security';

COMMENT ON TABLE tenant_session_policies IS 'Session configuration per tenant';
COMMENT ON COLUMN tenant_session_policies.idle_timeout_minutes IS 'Session invalidated after N minutes of inactivity (0 = disabled)';
COMMENT ON COLUMN tenant_session_policies.max_concurrent_sessions IS 'Max sessions per user (0 = unlimited)';
COMMENT ON COLUMN tenant_session_policies.remember_me_ttl_days IS 'Extended session duration when Remember Me is checked';
