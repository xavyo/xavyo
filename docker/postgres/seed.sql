-- Xavyo Suite - Test Data Seed Script
-- This script populates the database with test data for integration tests
--
-- Test Credentials:
--   Admin: admin@test.xavyo.com / Test123!
--   User:  user@test.xavyo.com / Test123!
--   Inactive: inactive@test.xavyo.com / Test123!

-- =============================================================================
-- Disable RLS temporarily for seeding
-- =============================================================================
SET session_replication_role = 'replica';

-- =============================================================================
-- Clear existing test data (for reset operations)
-- =============================================================================
DELETE FROM sessions WHERE tenant_id = '00000000-0000-0000-0000-000000000001';
DELETE FROM users WHERE tenant_id = '00000000-0000-0000-0000-000000000001';
DELETE FROM tenants WHERE id = '00000000-0000-0000-0000-000000000001';

-- =============================================================================
-- Test Tenant
-- =============================================================================
INSERT INTO tenants (id, name, slug, settings)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Xavyo Test Tenant',
    'test',
    '{"theme": "default", "features": ["all"]}'
) ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    slug = EXCLUDED.slug,
    settings = EXCLUDED.settings;

-- =============================================================================
-- Test Users
-- Password: Test123!
-- Argon2id hash generated with: cargo run -p xavyo-auth --example gen_hash
-- =============================================================================

-- Admin User
INSERT INTO users (id, tenant_id, email, password_hash, roles, is_active, email_verified, email_verified_at)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    '00000000-0000-0000-0000-000000000001',
    'admin@test.xavyo.com',
    '$argon2id$v=19$m=19456,t=2,p=1$liS80HrWaA9vZxSey4ckSQ$YjCmtgH+G+zW/+kJA0qrvqP+rSsNVYtStkWinslhvOU',
    '["admin", "user", "super_admin"]',
    true,
    true,
    NOW()
) ON CONFLICT (tenant_id, email) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    roles = EXCLUDED.roles,
    is_active = EXCLUDED.is_active,
    email_verified = EXCLUDED.email_verified,
    email_verified_at = EXCLUDED.email_verified_at;

-- Note: Roles are stored in JSONB column in users table, not a separate table

-- Regular User
INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, email_verified_at)
VALUES (
    '00000000-0000-0000-0000-000000000011',
    '00000000-0000-0000-0000-000000000001',
    'user@test.xavyo.com',
    '$argon2id$v=19$m=19456,t=2,p=1$liS80HrWaA9vZxSey4ckSQ$YjCmtgH+G+zW/+kJA0qrvqP+rSsNVYtStkWinslhvOU',
    true,
    true,
    NOW()
) ON CONFLICT (tenant_id, email) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    is_active = EXCLUDED.is_active,
    email_verified = EXCLUDED.email_verified,
    email_verified_at = EXCLUDED.email_verified_at;

-- Note: Roles are stored in JSONB column in users table

-- Inactive User (for testing disabled accounts)
INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, email_verified_at)
VALUES (
    '00000000-0000-0000-0000-000000000012',
    '00000000-0000-0000-0000-000000000001',
    'inactive@test.xavyo.com',
    '$argon2id$v=19$m=19456,t=2,p=1$liS80HrWaA9vZxSey4ckSQ$YjCmtgH+G+zW/+kJA0qrvqP+rSsNVYtStkWinslhvOU',
    false,
    true,
    NOW()
) ON CONFLICT (tenant_id, email) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    is_active = EXCLUDED.is_active,
    email_verified = EXCLUDED.email_verified,
    email_verified_at = EXCLUDED.email_verified_at;

-- Note: Roles are stored in JSONB column in users table

-- =============================================================================
-- Re-enable RLS
-- =============================================================================
SET session_replication_role = 'origin';

-- =============================================================================
-- Verify seed data
-- =============================================================================
DO $$
DECLARE
    tenant_count INT;
    user_count INT;
BEGIN
    SELECT COUNT(*) INTO tenant_count FROM tenants WHERE id = '00000000-0000-0000-0000-000000000001';
    SELECT COUNT(*) INTO user_count FROM users WHERE tenant_id = '00000000-0000-0000-0000-000000000001';

    IF tenant_count = 1 AND user_count = 3 THEN
        RAISE NOTICE 'Seed data loaded successfully: 1 tenant, 3 users';
    ELSE
        RAISE WARNING 'Seed data verification failed: % tenants, % users', tenant_count, user_count;
    END IF;
END
$$;
