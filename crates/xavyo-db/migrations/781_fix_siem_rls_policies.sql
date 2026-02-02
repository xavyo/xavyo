-- F078: Fix RLS policies to use NULLIF pattern consistent with migration 029.
--
-- The original migration used the old pattern:
--   USING (tenant_id = current_setting('app.current_tenant')::uuid)
--
-- This fix applies the corrected pattern with:
--   1. current_setting('app.current_tenant', true) — returns NULL if not set
--   2. NULLIF(..., '') — handles empty string case
--   3. Explicit FOR ALL + WITH CHECK clause

-- siem_destinations
DROP POLICY IF EXISTS siem_destinations_tenant_isolation ON siem_destinations;
CREATE POLICY siem_destinations_tenant_isolation ON siem_destinations
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- siem_export_events
DROP POLICY IF EXISTS siem_export_events_tenant_isolation ON siem_export_events;
CREATE POLICY siem_export_events_tenant_isolation ON siem_export_events
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- siem_delivery_health
DROP POLICY IF EXISTS siem_delivery_health_tenant_isolation ON siem_delivery_health;
CREATE POLICY siem_delivery_health_tenant_isolation ON siem_delivery_health
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- siem_batch_exports
DROP POLICY IF EXISTS siem_batch_exports_tenant_isolation ON siem_batch_exports;
CREATE POLICY siem_batch_exports_tenant_isolation ON siem_batch_exports
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- Add ON DELETE CASCADE on tenant FK for all four tables
-- (prevents orphaned rows when a tenant is deleted)
ALTER TABLE siem_destinations DROP CONSTRAINT IF EXISTS siem_destinations_tenant_id_fkey;
ALTER TABLE siem_destinations ADD CONSTRAINT siem_destinations_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE siem_export_events DROP CONSTRAINT IF EXISTS siem_export_events_tenant_id_fkey;
ALTER TABLE siem_export_events ADD CONSTRAINT siem_export_events_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE siem_delivery_health DROP CONSTRAINT IF EXISTS siem_delivery_health_tenant_id_fkey;
ALTER TABLE siem_delivery_health ADD CONSTRAINT siem_delivery_health_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE siem_batch_exports DROP CONSTRAINT IF EXISTS siem_batch_exports_tenant_id_fkey;
ALTER TABLE siem_batch_exports ADD CONSTRAINT siem_batch_exports_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
