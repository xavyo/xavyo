-- Fix RLS policies on 5 governance escalation/approval tables that reference
-- 'app.current_tenant_id' (incorrect) instead of 'app.current_tenant' (correct).
-- The middleware sets 'app.current_tenant', so these 5 policies never match,
-- causing INSERT/UPDATE/DELETE to fail with database errors.

-- gov_approval_groups
DROP POLICY IF EXISTS gov_approval_groups_tenant_isolation ON gov_approval_groups;
CREATE POLICY gov_approval_groups_tenant_isolation ON gov_approval_groups
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- gov_escalation_policies
DROP POLICY IF EXISTS gov_escalation_policies_tenant_isolation ON gov_escalation_policies;
CREATE POLICY gov_escalation_policies_tenant_isolation ON gov_escalation_policies
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- gov_escalation_rules
DROP POLICY IF EXISTS gov_escalation_rules_tenant_isolation ON gov_escalation_rules;
CREATE POLICY gov_escalation_rules_tenant_isolation ON gov_escalation_rules
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- gov_escalation_levels
DROP POLICY IF EXISTS gov_escalation_levels_tenant_isolation ON gov_escalation_levels;
CREATE POLICY gov_escalation_levels_tenant_isolation ON gov_escalation_levels
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- gov_escalation_events
DROP POLICY IF EXISTS gov_escalation_events_tenant_isolation ON gov_escalation_events;
CREATE POLICY gov_escalation_events_tenant_isolation ON gov_escalation_events
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
