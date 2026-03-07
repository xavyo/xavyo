-- Add optional application_id to gov_roles for application-scoped roles.
-- Existing roles get NULL (global/unscoped). Application-specific roles
-- (e.g., CRM roles) will have the application_id set.

ALTER TABLE gov_roles ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES gov_applications(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_gov_roles_tenant_app ON gov_roles(tenant_id, application_id);
