-- Migration: 031_fix_refresh_tokens_ip_address.sql
-- Purpose: Fix ip_address column type from inet to varchar
-- The code passes text but the column was inet type

ALTER TABLE refresh_tokens ALTER COLUMN ip_address TYPE VARCHAR(45);

COMMENT ON COLUMN refresh_tokens.ip_address IS 'IP address of the client that created the token (IPv4 or IPv6)';
