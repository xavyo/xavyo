-- Migration: 960_device_codes.sql
-- Feature: 096-device-code-oauth
-- Description: Device Authorization Grant (RFC 8628) storage

-- T001-T002: Device code status enum
CREATE TYPE device_code_status AS ENUM ('pending', 'authorized', 'denied', 'expired');

-- T001: Device codes table
CREATE TABLE IF NOT EXISTS device_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    device_code VARCHAR(64) NOT NULL,
    user_code VARCHAR(16) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    status device_code_status NOT NULL DEFAULT 'pending',
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_poll_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    authorized_at TIMESTAMPTZ,

    -- Unique constraints for code lookups
    CONSTRAINT device_codes_device_code_unique UNIQUE (device_code),
    CONSTRAINT device_codes_user_code_unique UNIQUE (user_code),

    -- Foreign key to oauth_clients (composite key with tenant)
    CONSTRAINT fk_device_codes_client FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients(tenant_id, client_id) ON DELETE CASCADE
);

-- Indexes for efficient queries
CREATE INDEX idx_device_codes_tenant_id ON device_codes(tenant_id);
CREATE INDEX idx_device_codes_expires_at ON device_codes(expires_at);
CREATE INDEX idx_device_codes_status ON device_codes(status) WHERE status = 'pending';

-- T003: Row-Level Security for tenant isolation
ALTER TABLE device_codes ENABLE ROW LEVEL SECURITY;

CREATE POLICY device_codes_tenant_isolation ON device_codes
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- T004: Cleanup function for expired device codes
CREATE OR REPLACE FUNCTION cleanup_expired_device_codes()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM device_codes
        WHERE expires_at < NOW()
        RETURNING 1
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;

    RETURN COALESCE(deleted_count, 0);
END;
$$ LANGUAGE plpgsql;

-- Comment for documentation
COMMENT ON TABLE device_codes IS 'RFC 8628 Device Authorization Grant - stores pending device authorizations';
COMMENT ON COLUMN device_codes.device_code IS 'Secret code for CLI polling (32 bytes URL-safe base64)';
COMMENT ON COLUMN device_codes.user_code IS 'User-facing code for browser entry (8 chars, no ambiguous chars)';
COMMENT ON COLUMN device_codes.interval_seconds IS 'Minimum seconds between polling requests';
