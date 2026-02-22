-- Migration: Make OAuth client_id unique per tenant instead of globally unique
-- Previously, Tenant A could register client_id="acme" and prevent Tenant B
-- from using it. Also enables cross-tenant enumeration.

-- Drop the global unique constraint on client_id
-- Must drop constraint first (it depends on the index), then the index
ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_client_id_key;
DROP INDEX IF EXISTS oauth_clients_client_id_key;

-- Add per-tenant unique constraint
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_clients_tenant_client_id
    ON oauth_clients (tenant_id, client_id);
