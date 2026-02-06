-- Migration 1181: Grant xavyo_app permissions and enforce RLS on ALL tables
--
-- Previously, the API connected as the superuser 'xavyo' which bypasses RLS.
-- This migration:
--   1. Grants 'xavyo_app' (a non-superuser, non-bypassrls role) full CRUD on all tables
--   2. Enables RLS on ALL tables (including recently-added IGA tables)
--   3. Creates tenant_isolation_policy on tables with tenant_id
--   4. Creates special policies for tables without tenant_id

-- 1. Grant USAGE on the public schema
GRANT USAGE ON SCHEMA public TO xavyo_app;

-- 2. Grant CRUD on ALL existing tables (except _sqlx_migrations which is admin-only)
DO $$
DECLARE
    tbl RECORD;
BEGIN
    FOR tbl IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND c.relname != '_sqlx_migrations'
        ORDER BY c.relname
    LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO xavyo_app', tbl.relname);
    END LOOP;
END $$;

-- 3. Grant USAGE + SELECT on ALL existing sequences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO xavyo_app;

-- 4. Set default privileges so future tables/sequences are automatically accessible
ALTER DEFAULT PRIVILEGES FOR ROLE xavyo IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO xavyo_app;

ALTER DEFAULT PRIVILEGES FOR ROLE xavyo IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO xavyo_app;

-- 5. Enable RLS on ALL tables and create tenant_isolation_policy for tables with tenant_id
DO $$
DECLARE
    tbl RECORD;
BEGIN
    -- Enable RLS on every table (idempotent)
    FOR tbl IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND c.relname != '_sqlx_migrations'
        ORDER BY c.relname
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl.relname);
    END LOOP;

    -- Create tenant_isolation_policy on tables WITH tenant_id that don't already have it
    FOR tbl IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND c.relname != '_sqlx_migrations'
          -- Has a tenant_id column
          AND EXISTS (
              SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
          )
          -- Does not already have tenant_isolation_policy
          AND NOT EXISTS (
              SELECT 1 FROM pg_policies p
              WHERE p.tablename = c.relname AND p.policyname = 'tenant_isolation_policy'
          )
        ORDER BY c.relname
    LOOP
        EXECUTE format(
            'CREATE POLICY tenant_isolation_policy ON %I FOR ALL TO xavyo_app USING (tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)',
            tbl.relname
        );
    END LOOP;
END $$;

-- 6. Special policies for tables WITHOUT tenant_id

-- tenants: allow read for tenant resolution, write only for current tenant
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'tenants' AND policyname = 'tenants_app_access') THEN
        EXECUTE 'CREATE POLICY tenants_app_access ON tenants FOR SELECT TO xavyo_app USING (true)';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'tenants' AND policyname = 'tenants_app_write') THEN
        EXECUTE 'CREATE POLICY tenants_app_write ON tenants FOR ALL TO xavyo_app USING (
            id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid
        )';
    END IF;
END $$;

-- user_roles: isolate via FK to users table
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'user_roles' AND policyname = 'user_roles_app_access') THEN
        EXECUTE 'CREATE POLICY user_roles_app_access ON user_roles FOR ALL TO xavyo_app USING (
            EXISTS (SELECT 1 FROM users u WHERE u.id = user_roles.user_id
                AND u.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)
        )';
    END IF;
END $$;

-- admin_permissions: system-level, read-only for all tenants
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'admin_permissions' AND policyname = 'admin_permissions_app_read') THEN
        EXECUTE 'CREATE POLICY admin_permissions_app_read ON admin_permissions FOR SELECT TO xavyo_app USING (true)';
    END IF;
END $$;

-- admin_role_template_permissions: system + tenant-scoped
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'admin_role_template_permissions' AND policyname = 'admin_role_template_perms_app') THEN
        EXECUTE 'CREATE POLICY admin_role_template_perms_app ON admin_role_template_permissions FOR ALL TO xavyo_app USING (true)';
    END IF;
END $$;

-- gov_approval_steps: linked via workflow_id to tenant-scoped workflows
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gov_approval_steps' AND policyname = 'gov_approval_steps_app') THEN
        EXECUTE 'CREATE POLICY gov_approval_steps_app ON gov_approval_steps FOR ALL TO xavyo_app USING (
            EXISTS (SELECT 1 FROM gov_approval_workflows w WHERE w.id = gov_approval_steps.workflow_id
                AND w.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)
        )';
    END IF;
END $$;

-- gov_batch_simulation_results: linked via simulation_id
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gov_batch_simulation_results' AND policyname = 'gov_batch_sim_results_app') THEN
        EXECUTE 'CREATE POLICY gov_batch_sim_results_app ON gov_batch_simulation_results FOR ALL TO xavyo_app USING (
            EXISTS (SELECT 1 FROM gov_batch_simulations bs WHERE bs.id = gov_batch_simulation_results.simulation_id
                AND bs.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)
        )';
    END IF;
END $$;

-- gov_certification_decisions: linked via item_id
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gov_certification_decisions' AND policyname = 'gov_cert_decisions_app') THEN
        EXECUTE 'CREATE POLICY gov_cert_decisions_app ON gov_certification_decisions FOR ALL TO xavyo_app USING (
            EXISTS (SELECT 1 FROM gov_certification_items ci WHERE ci.id = gov_certification_decisions.item_id
                AND ci.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)
        )';
    END IF;
END $$;

-- gov_correlation_candidates: linked via case_id
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gov_correlation_candidates' AND policyname = 'gov_corr_candidates_app') THEN
        EXECUTE 'CREATE POLICY gov_corr_candidates_app ON gov_correlation_candidates FOR ALL TO xavyo_app USING (
            EXISTS (SELECT 1 FROM gov_correlation_cases cc WHERE cc.id = gov_correlation_candidates.case_id
                AND cc.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)
        )';
    END IF;
END $$;

-- gov_policy_simulation_results: linked via simulation_id
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gov_policy_simulation_results' AND policyname = 'gov_policy_sim_results_app') THEN
        EXECUTE 'CREATE POLICY gov_policy_sim_results_app ON gov_policy_simulation_results FOR ALL TO xavyo_app USING (
            EXISTS (SELECT 1 FROM gov_policy_simulations ps WHERE ps.id = gov_policy_simulation_results.simulation_id
                AND ps.tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)
        )';
    END IF;
END $$;

-- processed_events: global event tracking, allow all
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'processed_events' AND policyname = 'processed_events_app') THEN
        EXECUTE 'CREATE POLICY processed_events_app ON processed_events FOR ALL TO xavyo_app USING (true)';
    END IF;
END $$;

-- 7. Replace all unsafe COALESCE-based policies with proper NULLIF pattern.
-- Some older migrations created policies like:
--   COALESCE(NULLIF(current_setting('app.current_tenant', true), '')::uuid, tenant_id)
-- The fallback to tenant_id is ALWAYS TRUE when setting is empty, bypassing isolation.
DO $$
DECLARE
    pol RECORD;
BEGIN
    FOR pol IN
        SELECT p.schemaname, p.tablename, p.policyname
        FROM pg_policies p
        WHERE p.schemaname = 'public'
          AND p.qual::text LIKE '%COALESCE%'
          -- Only fix tables that have tenant_id
          AND EXISTS (
              SELECT 1 FROM pg_attribute a
              JOIN pg_class c ON a.attrelid = c.oid
              JOIN pg_namespace n ON c.relnamespace = n.oid
              WHERE n.nspname = 'public' AND c.relname = p.tablename
                AND a.attname = 'tenant_id' AND NOT a.attisdropped
          )
    LOOP
        RAISE NOTICE 'Replacing unsafe COALESCE policy %.% on %', pol.schemaname, pol.policyname, pol.tablename;
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', pol.policyname, pol.tablename);
        -- Only create if tenant_isolation_policy doesn't already exist
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies p2
            WHERE p2.tablename = pol.tablename AND p2.policyname = 'tenant_isolation_policy'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation_policy ON %I USING (tenant_id = NULLIF(current_setting(''app.current_tenant'', true), '''')::uuid)',
                pol.tablename
            );
        END IF;
    END LOOP;
END $$;

-- Special case: tenant_plan_changes needs system tenant exception
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'tenant_plan_changes' AND qual::text LIKE '%COALESCE%'
    ) THEN
        DROP POLICY IF EXISTS tenant_plan_changes_isolation ON tenant_plan_changes;
        DROP POLICY IF EXISTS tenant_isolation_policy ON tenant_plan_changes;
        CREATE POLICY tenant_isolation_policy ON tenant_plan_changes USING (
            tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
            OR current_setting('app.current_tenant', true) = '00000000-0000-0000-0000-000000000001'
        );
    END IF;
END $$;

-- 8. Verify: count tables accessible to xavyo_app
DO $$
DECLARE
    accessible_count INT;
    total_count INT;
BEGIN
    SELECT count(*) INTO total_count
    FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname != '_sqlx_migrations';

    SELECT count(*) INTO accessible_count
    FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname != '_sqlx_migrations'
      AND has_table_privilege('xavyo_app', c.oid, 'SELECT');

    RAISE NOTICE 'xavyo_app can access % of % tables', accessible_count, total_count;

    IF accessible_count < total_count THEN
        RAISE WARNING 'xavyo_app is missing access to % tables!', total_count - accessible_count;
    END IF;
END $$;
