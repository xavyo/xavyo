-- Migration: Create users table with Row-Level Security
-- Description: User accounts with tenant isolation via RLS policies

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Unique constraint: email must be unique within each tenant
    CONSTRAINT users_tenant_email_unique UNIQUE (tenant_id, email)
);

-- Index for tenant_id lookups (critical for RLS performance)
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);

-- Index for email lookups within tenant context
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Index for created_at (useful for listing/sorting)
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- Enable Row-Level Security on the users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (defense in depth)
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- RLS Policy: Tenant isolation
-- Only rows where tenant_id matches the current session tenant are visible
-- If no tenant context is set, current_setting returns NULL and no rows match (fail-safe)
CREATE POLICY tenant_isolation_policy ON users
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE users IS 'User accounts belonging to tenants';
COMMENT ON COLUMN users.id IS 'Unique identifier for the user';
COMMENT ON COLUMN users.tenant_id IS 'Reference to the tenant this user belongs to';
COMMENT ON COLUMN users.email IS 'User email address (unique per tenant)';
COMMENT ON COLUMN users.password_hash IS 'Argon2id hashed password';
COMMENT ON COLUMN users.created_at IS 'Timestamp when user was created';
