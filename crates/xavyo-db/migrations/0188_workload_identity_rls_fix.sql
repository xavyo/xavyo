-- Migration: Fix overly permissive RLS on workload identity tables
-- These 4 tables had OR conditions allowing access when tenant context is NOT set.
-- This is dangerous: if middleware fails, queries return ALL rows across tenants.

-- 1. identity_provider_configs
DROP POLICY IF EXISTS tenant_isolation_identity_provider_configs ON identity_provider_configs;
DROP POLICY IF EXISTS identity_provider_configs_tenant_isolation ON identity_provider_configs;
DROP POLICY IF EXISTS tenant_isolation ON identity_provider_configs;
CREATE POLICY tenant_isolation ON identity_provider_configs
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 2. iam_role_mappings
DROP POLICY IF EXISTS tenant_isolation_iam_role_mappings ON iam_role_mappings;
DROP POLICY IF EXISTS iam_role_mappings_tenant_isolation ON iam_role_mappings;
DROP POLICY IF EXISTS tenant_isolation ON iam_role_mappings;
CREATE POLICY tenant_isolation ON iam_role_mappings
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 3. identity_credential_requests
DROP POLICY IF EXISTS tenant_isolation_identity_credential_requests ON identity_credential_requests;
DROP POLICY IF EXISTS identity_credential_requests_tenant_isolation ON identity_credential_requests;
DROP POLICY IF EXISTS tenant_isolation ON identity_credential_requests;
CREATE POLICY tenant_isolation ON identity_credential_requests
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- 4. identity_audit_events
DROP POLICY IF EXISTS tenant_isolation_identity_audit_events ON identity_audit_events;
DROP POLICY IF EXISTS identity_audit_events_tenant_isolation ON identity_audit_events;
DROP POLICY IF EXISTS tenant_isolation ON identity_audit_events;
CREATE POLICY tenant_isolation ON identity_audit_events
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
