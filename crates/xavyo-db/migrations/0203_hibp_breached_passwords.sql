-- Migration: 0203_hibp_breached_passwords.sql
-- Feature: NIST 800-63B breached password check
-- Description: Add check_breached_passwords column to tenant_password_policies

ALTER TABLE tenant_password_policies
    ADD COLUMN IF NOT EXISTS check_breached_passwords BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN tenant_password_policies.check_breached_passwords
    IS 'Whether to check passwords against the HIBP breached password database (NIST 800-63B)';
