-- Migration: 022_device_management.sql
-- Feature: F026 - Device Management
-- Description: Extend user_devices table with trust management columns

-- ============================================================================
-- Part 1: Add new columns to user_devices
-- ============================================================================

ALTER TABLE user_devices
    ADD COLUMN IF NOT EXISTS device_type VARCHAR(20),
    ADD COLUMN IF NOT EXISTS browser VARCHAR(50),
    ADD COLUMN IF NOT EXISTS browser_version VARCHAR(20),
    ADD COLUMN IF NOT EXISTS os VARCHAR(50),
    ADD COLUMN IF NOT EXISTS os_version VARCHAR(20),
    ADD COLUMN IF NOT EXISTS is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS trust_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_ip_address VARCHAR(45),
    ADD COLUMN IF NOT EXISTS last_geo_country VARCHAR(2),
    ADD COLUMN IF NOT EXISTS last_geo_city VARCHAR(100),
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- ============================================================================
-- Part 2: Add constraint for device_type
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_device_type'
    ) THEN
        ALTER TABLE user_devices
            ADD CONSTRAINT chk_device_type
            CHECK (device_type IS NULL OR device_type IN ('desktop', 'mobile', 'tablet'));
    END IF;
END $$;

-- ============================================================================
-- Part 3: Add indexes for performance
-- ============================================================================

-- Index for active (non-revoked) devices
CREATE INDEX IF NOT EXISTS idx_user_devices_active
    ON user_devices(tenant_id, user_id)
    WHERE revoked_at IS NULL;

-- Index for trusted devices (for MFA bypass lookup)
CREATE INDEX IF NOT EXISTS idx_user_devices_trusted
    ON user_devices(tenant_id, user_id)
    WHERE is_trusted = TRUE AND revoked_at IS NULL;

-- ============================================================================
-- Part 4: Add DELETE policy for user_devices (for revocation)
-- ============================================================================

DROP POLICY IF EXISTS tenant_isolation_user_devices_delete ON user_devices;
CREATE POLICY tenant_isolation_user_devices_delete ON user_devices
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- Part 5: Comments for documentation
-- ============================================================================

COMMENT ON COLUMN user_devices.device_type IS 'Device type: desktop, mobile, tablet';
COMMENT ON COLUMN user_devices.browser IS 'Browser name from User-Agent';
COMMENT ON COLUMN user_devices.browser_version IS 'Browser version from User-Agent';
COMMENT ON COLUMN user_devices.os IS 'Operating system from User-Agent';
COMMENT ON COLUMN user_devices.os_version IS 'OS version from User-Agent';
COMMENT ON COLUMN user_devices.is_trusted IS 'True if device is trusted for MFA bypass';
COMMENT ON COLUMN user_devices.trust_expires_at IS 'Trust expiration timestamp (NULL = permanent)';
COMMENT ON COLUMN user_devices.last_ip_address IS 'Last IP address used from this device';
COMMENT ON COLUMN user_devices.last_geo_country IS 'Last geo country code (ISO 3166-1 alpha-2)';
COMMENT ON COLUMN user_devices.last_geo_city IS 'Last geo city name';
COMMENT ON COLUMN user_devices.revoked_at IS 'Timestamp when device was revoked (soft delete)';
