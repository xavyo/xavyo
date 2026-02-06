-- Migration: Add composite indexes for high-traffic query paths
--
-- 1. failed_login_attempts: brute force detection query uses
--    WHERE tenant_id = $1 AND email = $2 AND created_at >= $3
--    Existing separate indexes on (tenant_id, created_at) and (email, created_at)
--    don't cover this 3-column filter efficiently.
--
-- 2. users: login lookup query uses WHERE tenant_id = $1 AND email = $2
--    Existing idx_users_email is single-column on (email) only.

-- Composite index for brute force detection count query
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_failed_login_tenant_email_time
    ON failed_login_attempts(tenant_id, email, created_at DESC);

-- Composite index for tenant-scoped user email lookups (login flow)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant_email
    ON users(tenant_id, email);
