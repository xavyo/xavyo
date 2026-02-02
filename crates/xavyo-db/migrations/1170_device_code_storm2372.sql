-- Migration: 1170_device_code_storm2372.sql
-- Feature: 117-storm2372-remediation
-- Description: Add origin context fields to device_codes for Storm-2372 phishing defense

-- T001: Add origin context columns to device_codes table
-- These fields capture information about the request that created the device code,
-- enabling users to detect potential phishing attacks on the approval page.

ALTER TABLE device_codes
ADD COLUMN IF NOT EXISTS origin_ip VARCHAR(45),
ADD COLUMN IF NOT EXISTS origin_user_agent TEXT,
ADD COLUMN IF NOT EXISTS origin_country VARCHAR(2);

-- Index for potential IP-based queries (future risk assessment)
CREATE INDEX IF NOT EXISTS idx_device_codes_origin_ip ON device_codes(origin_ip) WHERE origin_ip IS NOT NULL;

-- Comments for documentation
COMMENT ON COLUMN device_codes.origin_ip IS 'IP address from which the device code was requested (IPv4 or IPv6)';
COMMENT ON COLUMN device_codes.origin_user_agent IS 'User-Agent header from the device code request';
COMMENT ON COLUMN device_codes.origin_country IS 'ISO 3166-1 alpha-2 country code of origin IP (XX if unknown)';
