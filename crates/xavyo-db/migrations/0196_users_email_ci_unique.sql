-- C-1: Replace case-sensitive email uniqueness constraint with case-insensitive one.
--
-- The original constraint `users_tenant_email_unique UNIQUE (tenant_id, email)` is
-- case-sensitive. The application normalizes emails to lowercase before INSERT, but
-- direct DB access or SCIM provisioning could create rows with mixed-case emails that
-- conflict on lookup but not on the constraint. This migration replaces the constraint
-- with a unique index on `(tenant_id, LOWER(email))`.

-- Drop the old case-sensitive uniqueness constraint
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_email_unique;

-- Create case-insensitive unique index (replaces both the old constraint and the
-- performance index from migration 0194)
DROP INDEX IF EXISTS idx_users_tenant_email_lower;
CREATE UNIQUE INDEX users_tenant_email_ci_unique ON users (tenant_id, LOWER(email));
