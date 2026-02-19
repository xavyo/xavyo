-- Migration: Fix overly permissive RLS on federated_auth_sessions
-- The original migration 0147 used USING(true) which allows the xavyo_app role
-- to read ALL rows across all tenants when no tenant context is set.
-- This replaces it with the proper NULLIF pattern.

DROP POLICY IF EXISTS tenant_isolation_federated_auth_sessions ON federated_auth_sessions;
DROP POLICY IF EXISTS federated_auth_sessions_tenant_isolation ON federated_auth_sessions;
DROP POLICY IF EXISTS tenant_isolation ON federated_auth_sessions;
CREATE POLICY tenant_isolation ON federated_auth_sessions
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
