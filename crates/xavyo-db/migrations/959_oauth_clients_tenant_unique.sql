-- Migration: 959_oauth_clients_tenant_unique.sql
-- Description: Add unique constraint on (tenant_id, client_id) to support foreign key from device_codes

-- Add unique constraint on (tenant_id, client_id) for foreign key support
-- Note: client_id already has a UNIQUE constraint, so adding tenant_id doesn't reduce uniqueness
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_clients_tenant_client_id
    ON oauth_clients(tenant_id, client_id);
