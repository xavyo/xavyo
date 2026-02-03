-- Xavyo Suite - Test Data Seed Script
-- NOTE: Seed data is now created by the API bootstrap process and tests
-- This file is intentionally minimal - schema managed by SQLx migrations

-- Enable required extensions (in case init.sql didn't run)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
