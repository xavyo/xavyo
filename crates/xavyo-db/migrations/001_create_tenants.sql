-- Migration: Create tenants table
-- Description: Initial tenant management table for multi-tenant system

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for slug lookups (used for tenant resolution)
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- Index for created_at (useful for listing/sorting)
CREATE INDEX IF NOT EXISTS idx_tenants_created_at ON tenants(created_at);

COMMENT ON TABLE tenants IS 'Organizations using the Xavyo system';
COMMENT ON COLUMN tenants.id IS 'Unique identifier for the tenant';
COMMENT ON COLUMN tenants.name IS 'Display name of the tenant organization';
COMMENT ON COLUMN tenants.slug IS 'URL-safe unique identifier (e.g., acme-corp)';
COMMENT ON COLUMN tenants.settings IS 'Tenant-specific configuration as JSON';
COMMENT ON COLUMN tenants.created_at IS 'Timestamp when tenant was created';
