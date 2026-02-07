-- Fix RLS policies on api_key_usage tables to use NULLIF pattern.
-- Migration 997 used the old pattern: current_setting('app.current_tenant', true)::uuid
-- which fails with a cast error when the setting is an empty string.
-- This applies the same fix from migration 1182 to these 3 tables.

-- api_key_usage
DROP POLICY IF EXISTS api_key_usage_tenant_isolation ON api_key_usage;
CREATE POLICY api_key_usage_tenant_isolation ON api_key_usage
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- api_key_usage_hourly
DROP POLICY IF EXISTS api_key_usage_hourly_tenant_isolation ON api_key_usage_hourly;
CREATE POLICY api_key_usage_hourly_tenant_isolation ON api_key_usage_hourly
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- api_key_usage_daily
DROP POLICY IF EXISTS api_key_usage_daily_tenant_isolation ON api_key_usage_daily;
CREATE POLICY api_key_usage_daily_tenant_isolation ON api_key_usage_daily
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);
