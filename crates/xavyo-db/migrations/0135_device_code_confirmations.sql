-- Migration: 1171_device_code_confirmations.sql
-- Feature: F117 Storm-2372 Remediation - User Story 2
-- Purpose: Email confirmation for suspicious device code approvals
--
-- This table stores email confirmation tokens required when a user
-- attempts to approve a device code from a suspicious IP address
-- (different from the origin IP where the code was requested).

-- Create device_code_confirmations table
CREATE TABLE IF NOT EXISTS device_code_confirmations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant isolation (RLS)
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Link to the device code being confirmed
    device_code_id UUID NOT NULL REFERENCES device_codes(id) ON DELETE CASCADE,

    -- User who needs to confirm
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Confirmation token (SHA-256 hash stored, not plaintext)
    -- Token is 32 bytes random, base64url encoded = 43 chars
    confirmation_token_hash VARCHAR(64) NOT NULL,

    -- IP address from which confirmation was requested
    requested_from_ip VARCHAR(45),

    -- Status tracking
    confirmed_at TIMESTAMPTZ,

    -- Rate limiting for resend
    last_sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    send_count INTEGER NOT NULL DEFAULT 1,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes',

    -- Constraints
    CONSTRAINT valid_send_count CHECK (send_count >= 1 AND send_count <= 5)
);

-- Index for token lookup (primary lookup path)
CREATE INDEX IF NOT EXISTS idx_device_code_confirmations_token_hash
    ON device_code_confirmations(confirmation_token_hash);

-- Index for device code lookup
CREATE INDEX IF NOT EXISTS idx_device_code_confirmations_device_code
    ON device_code_confirmations(device_code_id);

-- Index for user lookup
CREATE INDEX IF NOT EXISTS idx_device_code_confirmations_user
    ON device_code_confirmations(tenant_id, user_id);

-- Index for cleanup of expired confirmations
CREATE INDEX IF NOT EXISTS idx_device_code_confirmations_expires
    ON device_code_confirmations(expires_at)
    WHERE confirmed_at IS NULL;

-- Enable Row Level Security
ALTER TABLE device_code_confirmations ENABLE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
-- Only rows belonging to the current tenant are visible
CREATE POLICY device_code_confirmations_tenant_isolation
    ON device_code_confirmations
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Comment for documentation
COMMENT ON TABLE device_code_confirmations IS
    'Storm-2372 remediation: Email confirmations for suspicious device code approvals (F117)';
COMMENT ON COLUMN device_code_confirmations.confirmation_token_hash IS
    'SHA-256 hash of the confirmation token sent via email';
COMMENT ON COLUMN device_code_confirmations.requested_from_ip IS
    'IP address from which the user attempted to approve (for audit)';
COMMENT ON COLUMN device_code_confirmations.send_count IS
    'Number of times confirmation email was sent (rate limit: max 5)';
