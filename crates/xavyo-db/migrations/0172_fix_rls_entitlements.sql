-- Fix RLS policies on gov_entitlements and gov_entitlement_assignments.
-- These tables were missed in migration 1182 (NULLIF pattern fix).
-- The old pattern `current_setting('app.current_tenant', true)::uuid` fails
-- when the setting is an empty string. The NULLIF pattern handles this gracefully.

-- gov_entitlements: fix SELECT, INSERT, UPDATE, DELETE policies
DROP POLICY IF EXISTS gov_entitlements_tenant_isolation_select ON gov_entitlements;
CREATE POLICY gov_entitlements_tenant_isolation_select ON gov_entitlements
    FOR SELECT
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS gov_entitlements_tenant_isolation_insert ON gov_entitlements;
CREATE POLICY gov_entitlements_tenant_isolation_insert ON gov_entitlements
    FOR INSERT
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS gov_entitlements_tenant_isolation_update ON gov_entitlements;
CREATE POLICY gov_entitlements_tenant_isolation_update ON gov_entitlements
    FOR UPDATE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS gov_entitlements_tenant_isolation_delete ON gov_entitlements;
CREATE POLICY gov_entitlements_tenant_isolation_delete ON gov_entitlements
    FOR DELETE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- gov_entitlement_assignments: fix SELECT, INSERT, UPDATE, DELETE policies
DROP POLICY IF EXISTS gov_assignments_tenant_isolation_select ON gov_entitlement_assignments;
CREATE POLICY gov_assignments_tenant_isolation_select ON gov_entitlement_assignments
    FOR SELECT
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS gov_assignments_tenant_isolation_insert ON gov_entitlement_assignments;
CREATE POLICY gov_assignments_tenant_isolation_insert ON gov_entitlement_assignments
    FOR INSERT
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS gov_assignments_tenant_isolation_update ON gov_entitlement_assignments;
CREATE POLICY gov_assignments_tenant_isolation_update ON gov_entitlement_assignments
    FOR UPDATE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

DROP POLICY IF EXISTS gov_assignments_tenant_isolation_delete ON gov_entitlement_assignments;
CREATE POLICY gov_assignments_tenant_isolation_delete ON gov_entitlement_assignments
    FOR DELETE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
