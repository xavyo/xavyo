-- Migration 0193: Add WITH CHECK clauses to SCIM table RLS policies
--
-- SCIM tables (from migration 0016, updated by 0029) have USING clauses but
-- lack WITH CHECK clauses on INSERT/UPDATE. This allows rows to be inserted
-- with mismatched tenant_id values, bypassing RLS isolation.
--
-- Tables: scim_tokens, scim_attribute_mappings, scim_audit_logs

-- scim_tokens
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_tokens;
CREATE POLICY tenant_isolation_policy ON scim_tokens
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- scim_attribute_mappings
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_attribute_mappings;
CREATE POLICY tenant_isolation_policy ON scim_attribute_mappings
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- scim_audit_logs
DROP POLICY IF EXISTS tenant_isolation_policy ON scim_audit_logs;
CREATE POLICY tenant_isolation_policy ON scim_audit_logs
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
