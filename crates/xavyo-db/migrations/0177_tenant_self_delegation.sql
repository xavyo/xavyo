-- Add tenant-level control for self-service NHI delegation.
-- When true, users can create delegation grants for their own identity.
-- When false, only admins/governance roles can create grants.
ALTER TABLE tenants ADD COLUMN allow_self_delegation BOOLEAN NOT NULL DEFAULT true;
