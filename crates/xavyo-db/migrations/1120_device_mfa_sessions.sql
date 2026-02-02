-- F112: Device MFA sessions table
-- Stores temporary MFA session state during device code login flow

CREATE TABLE IF NOT EXISTS device_mfa_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_code VARCHAR(9) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for tenant isolation
CREATE INDEX IF NOT EXISTS idx_device_mfa_sessions_tenant ON device_mfa_sessions(tenant_id);

-- Index for expiry cleanup
CREATE INDEX IF NOT EXISTS idx_device_mfa_sessions_expires ON device_mfa_sessions(expires_at);

-- Enable RLS
ALTER TABLE device_mfa_sessions ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
CREATE POLICY device_mfa_sessions_tenant_isolation ON device_mfa_sessions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON device_mfa_sessions TO authenticated;
