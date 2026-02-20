-- Migration 0191: Add WITH CHECK to RLS policies on social_connections and tenant_social_providers.
--
-- The existing RLS policies use USING but not WITH CHECK, meaning the policy protects
-- SELECT/UPDATE/DELETE (row visibility) but does not enforce the tenant constraint on INSERT
-- at the database level. Adding WITH CHECK ensures INSERT operations are also tenant-isolated.
--
-- See also: migration 0186 which did the same fix for a2a_tasks.

-- social_connections
DROP POLICY IF EXISTS tenant_isolation_policy ON social_connections;
CREATE POLICY tenant_isolation_policy ON social_connections
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- tenant_social_providers
DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_social_providers;
CREATE POLICY tenant_isolation_policy ON tenant_social_providers
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
