-- Migration: 1172_known_user_ips.sql
-- Feature: F117 Storm-2372 Remediation - User Story 3
-- Purpose: Track known IP addresses per user for risk scoring
--
-- This table stores the IP addresses that users have successfully authenticated from.
-- It's used to calculate risk scores by detecting new or unfamiliar locations.

-- Create known_user_ips table
CREATE TABLE IF NOT EXISTS known_user_ips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant isolation (RLS)
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- User whose known IPs we're tracking
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- The IP address (IPv4 or IPv6)
    ip_address VARCHAR(45) NOT NULL,

    -- Country code extracted from this IP (ISO 3166-1 alpha-2 or CloudFlare codes)
    country_code VARCHAR(2),

    -- Timestamps
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- How many times we've seen this IP for this user
    access_count INTEGER NOT NULL DEFAULT 1,

    -- Whether this IP is trusted (verified by user or admin)
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,

    -- Constraints
    CONSTRAINT unique_user_ip UNIQUE (tenant_id, user_id, ip_address),
    CONSTRAINT valid_access_count CHECK (access_count >= 1)
);

-- Index for user IP lookup (primary use case: checking if IP is known)
CREATE INDEX IF NOT EXISTS idx_known_user_ips_user_ip
    ON known_user_ips(tenant_id, user_id, ip_address);

-- Index for user's known IPs list
CREATE INDEX IF NOT EXISTS idx_known_user_ips_user
    ON known_user_ips(tenant_id, user_id);

-- Index for cleanup of old/unused IPs (last_seen_at for retention policies)
CREATE INDEX IF NOT EXISTS idx_known_user_ips_last_seen
    ON known_user_ips(last_seen_at);

-- Enable Row Level Security
ALTER TABLE known_user_ips ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
-- Only rows belonging to the current tenant are visible
CREATE POLICY known_user_ips_tenant_isolation
    ON known_user_ips
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Comment for documentation
COMMENT ON TABLE known_user_ips IS
    'Storm-2372 remediation: Track known user IP addresses for risk scoring (F117)';
COMMENT ON COLUMN known_user_ips.ip_address IS
    'IPv4 or IPv6 address from successful authentication';
COMMENT ON COLUMN known_user_ips.country_code IS
    'ISO 3166-1 alpha-2 country code or CloudFlare codes (T1, A1, A2)';
COMMENT ON COLUMN known_user_ips.access_count IS
    'Number of successful authentications from this IP';
COMMENT ON COLUMN known_user_ips.is_trusted IS
    'Whether this IP has been explicitly trusted by user or admin';
