-- Migration: 950_system_tenant_bootstrap.sql
-- Feature: F095 - System Tenant Bootstrap
-- Description: Add tenant_type column and protection triggers for system tenant

-- T001: Add tenant_type enum
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tenant_type') THEN
        CREATE TYPE tenant_type AS ENUM ('user', 'system');
    END IF;
END
$$;

-- T001: Add tenant_type column with default 'user' for existing tenants
ALTER TABLE tenants
ADD COLUMN IF NOT EXISTS tenant_type tenant_type NOT NULL DEFAULT 'user';

-- T002: Create index for efficient filtering by tenant type
CREATE INDEX IF NOT EXISTS idx_tenants_type ON tenants(tenant_type);

-- T003: Add unique partial index to prevent duplicate system tenants
-- Only one tenant can have tenant_type = 'system'
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_system_unique
ON tenants(tenant_type)
WHERE tenant_type = 'system';

-- T004: Trigger function to prevent deletion of system tenant
CREATE OR REPLACE FUNCTION prevent_system_tenant_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.tenant_type = 'system' THEN
        RAISE EXCEPTION 'Cannot delete system tenant: system tenants are protected infrastructure';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for delete prevention
DROP TRIGGER IF EXISTS no_delete_system_tenant ON tenants;
CREATE TRIGGER no_delete_system_tenant
BEFORE DELETE ON tenants
FOR EACH ROW
EXECUTE FUNCTION prevent_system_tenant_delete();

-- T005: Trigger function to prevent modification of system tenant critical fields
CREATE OR REPLACE FUNCTION prevent_system_tenant_modify()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.tenant_type = 'system' THEN
        -- Prevent changing id, slug, or tenant_type
        IF NEW.id != OLD.id THEN
            RAISE EXCEPTION 'Cannot modify system tenant id';
        END IF;
        IF NEW.slug != OLD.slug THEN
            RAISE EXCEPTION 'Cannot modify system tenant slug';
        END IF;
        IF NEW.tenant_type != OLD.tenant_type THEN
            RAISE EXCEPTION 'Cannot modify system tenant type';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for modification prevention
DROP TRIGGER IF EXISTS no_modify_system_tenant ON tenants;
CREATE TRIGGER no_modify_system_tenant
BEFORE UPDATE ON tenants
FOR EACH ROW
EXECUTE FUNCTION prevent_system_tenant_modify();
