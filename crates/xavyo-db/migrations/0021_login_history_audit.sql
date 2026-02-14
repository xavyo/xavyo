-- Migration: 021_login_history_audit.sql
-- Feature: F025 - Login History & Audit
-- Description: Create tables for comprehensive login audit trail and security alerts

-- ============================================================================
-- Part 1: Login Attempts table (comprehensive audit)
-- ============================================================================

CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,  -- NULL for unknown emails
    email VARCHAR(255) NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(50),                            -- NULL if success
    auth_method VARCHAR(20) NOT NULL DEFAULT 'password',   -- password, social, sso, mfa, refresh
    ip_address VARCHAR(45),                                -- IPv4 or IPv6
    user_agent TEXT,
    device_fingerprint VARCHAR(64),                        -- SHA-256 hash
    geo_country VARCHAR(2),                                -- ISO 3166-1 alpha-2
    geo_city VARCHAR(100),
    is_new_device BOOLEAN NOT NULL DEFAULT false,
    is_new_location BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Constraints
    CONSTRAINT chk_auth_method CHECK (auth_method IN ('password', 'social', 'sso', 'mfa', 'refresh')),
    CONSTRAINT chk_failure_reason_on_failure CHECK (success = true OR failure_reason IS NOT NULL)
);

-- Indexes for login_attempts
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
    ON login_attempts(tenant_id, user_id, created_at DESC)
    WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_login_attempts_tenant_time
    ON login_attempts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_email
    ON login_attempts(tenant_id, email, created_at DESC);

-- ============================================================================
-- Part 2: Security Alerts table
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alert_type VARCHAR(30) NOT NULL,                       -- new_device, new_location, failed_attempts, password_change, mfa_disabled
    severity VARCHAR(10) NOT NULL DEFAULT 'info',          -- info, warning, critical
    title VARCHAR(200) NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Constraints
    CONSTRAINT chk_alert_type CHECK (alert_type IN ('new_device', 'new_location', 'failed_attempts', 'password_change', 'mfa_disabled')),
    CONSTRAINT chk_severity CHECK (severity IN ('info', 'warning', 'critical'))
);

-- Indexes for security_alerts
CREATE INDEX IF NOT EXISTS idx_security_alerts_user_time
    ON security_alerts(tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_alerts_unacked
    ON security_alerts(tenant_id, user_id)
    WHERE acknowledged_at IS NULL;

-- ============================================================================
-- Part 3: User Devices table (device tracking)
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(64) NOT NULL,               -- SHA-256 hash
    device_name VARCHAR(100),                              -- User-provided name
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    login_count INTEGER NOT NULL DEFAULT 1,

    -- Unique constraint per user per device
    CONSTRAINT uq_user_device UNIQUE (tenant_id, user_id, device_fingerprint)
);

-- Index for device lookup
CREATE INDEX IF NOT EXISTS idx_user_devices_lookup
    ON user_devices(tenant_id, user_id, device_fingerprint);

-- ============================================================================
-- Part 4: User Locations table (location tracking)
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    country VARCHAR(2) NOT NULL,                           -- ISO 3166-1 alpha-2
    city VARCHAR(100) NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    login_count INTEGER NOT NULL DEFAULT 1,

    -- Unique constraint per user per location
    CONSTRAINT uq_user_location UNIQUE (tenant_id, user_id, country, city)
);

-- Index for location lookup
CREATE INDEX IF NOT EXISTS idx_user_locations_lookup
    ON user_locations(tenant_id, user_id, country, city);

-- ============================================================================
-- Part 5: Row Level Security
-- ============================================================================

-- Enable RLS on new tables
ALTER TABLE login_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_locations ENABLE ROW LEVEL SECURITY;

-- RLS for login_attempts
DROP POLICY IF EXISTS tenant_isolation_login_attempts_select ON login_attempts;
CREATE POLICY tenant_isolation_login_attempts_select ON login_attempts
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_login_attempts_insert ON login_attempts;
CREATE POLICY tenant_isolation_login_attempts_insert ON login_attempts
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for security_alerts
DROP POLICY IF EXISTS tenant_isolation_security_alerts_select ON security_alerts;
CREATE POLICY tenant_isolation_security_alerts_select ON security_alerts
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_security_alerts_insert ON security_alerts;
CREATE POLICY tenant_isolation_security_alerts_insert ON security_alerts
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_security_alerts_update ON security_alerts;
CREATE POLICY tenant_isolation_security_alerts_update ON security_alerts
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for user_devices
DROP POLICY IF EXISTS tenant_isolation_user_devices_select ON user_devices;
CREATE POLICY tenant_isolation_user_devices_select ON user_devices
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_user_devices_insert ON user_devices;
CREATE POLICY tenant_isolation_user_devices_insert ON user_devices
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_user_devices_update ON user_devices;
CREATE POLICY tenant_isolation_user_devices_update ON user_devices
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS for user_locations
DROP POLICY IF EXISTS tenant_isolation_user_locations_select ON user_locations;
CREATE POLICY tenant_isolation_user_locations_select ON user_locations
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_user_locations_insert ON user_locations;
CREATE POLICY tenant_isolation_user_locations_insert ON user_locations
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation_user_locations_update ON user_locations;
CREATE POLICY tenant_isolation_user_locations_update ON user_locations
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 6: Comments for documentation
-- ============================================================================

-- Tables
COMMENT ON TABLE login_attempts IS 'Comprehensive audit log of all login attempts (successful and failed)';
COMMENT ON TABLE security_alerts IS 'User-facing security notifications for suspicious activity';
COMMENT ON TABLE user_devices IS 'Known devices per user for new device detection';
COMMENT ON TABLE user_locations IS 'Known geo-locations per user for new location detection';

-- login_attempts columns
COMMENT ON COLUMN login_attempts.success IS 'True if authentication succeeded';
COMMENT ON COLUMN login_attempts.failure_reason IS 'Reason code if authentication failed';
COMMENT ON COLUMN login_attempts.auth_method IS 'Authentication method: password, social, sso, mfa, refresh';
COMMENT ON COLUMN login_attempts.device_fingerprint IS 'SHA-256 hash of client-provided device fingerprint';
COMMENT ON COLUMN login_attempts.geo_country IS 'ISO 3166-1 alpha-2 country code from IP geo-lookup';
COMMENT ON COLUMN login_attempts.geo_city IS 'City name from IP geo-lookup';
COMMENT ON COLUMN login_attempts.is_new_device IS 'True if first login from this device fingerprint';
COMMENT ON COLUMN login_attempts.is_new_location IS 'True if first login from this location';

-- security_alerts columns
COMMENT ON COLUMN security_alerts.alert_type IS 'Alert type: new_device, new_location, failed_attempts, password_change, mfa_disabled';
COMMENT ON COLUMN security_alerts.severity IS 'Severity level: info, warning, critical';
COMMENT ON COLUMN security_alerts.metadata IS 'Additional context data in JSON format';
COMMENT ON COLUMN security_alerts.acknowledged_at IS 'Timestamp when user acknowledged the alert';

-- user_devices columns
COMMENT ON COLUMN user_devices.device_fingerprint IS 'SHA-256 hash of client device fingerprint';
COMMENT ON COLUMN user_devices.device_name IS 'Optional user-provided device name';
COMMENT ON COLUMN user_devices.login_count IS 'Number of logins from this device';

-- user_locations columns
COMMENT ON COLUMN user_locations.country IS 'ISO 3166-1 alpha-2 country code';
COMMENT ON COLUMN user_locations.city IS 'City name';
COMMENT ON COLUMN user_locations.login_count IS 'Number of logins from this location';
