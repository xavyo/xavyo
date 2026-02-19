-- Migration: Add WITH CHECK clause to a2a_tasks RLS policy
-- The original policy (0101) only had USING, missing WITH CHECK for INSERT/UPDATE

DROP POLICY IF EXISTS a2a_tasks_tenant_isolation ON a2a_tasks;

CREATE POLICY a2a_tasks_tenant_isolation ON a2a_tasks
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
