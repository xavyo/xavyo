-- Xavyo Suite - Database Initialization Script
-- This script runs on first container startup to configure PostgreSQL
-- NOTE: Schema is managed by SQLx migrations, not this file

-- =============================================================================
-- Extensions
-- =============================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- Create application user role (non-superuser, for RLS testing)
-- =============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'xavyo_app') THEN
        CREATE ROLE xavyo_app WITH LOGIN PASSWORD 'xavyo_app_password' NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

-- =============================================================================
-- Grant permissions
-- =============================================================================
GRANT ALL PRIVILEGES ON DATABASE xavyo_test TO xavyo;
GRANT ALL PRIVILEGES ON DATABASE xavyo_test TO xavyo_app;
GRANT USAGE ON SCHEMA public TO xavyo_app;

-- Schema will be created by SQLx migrations
