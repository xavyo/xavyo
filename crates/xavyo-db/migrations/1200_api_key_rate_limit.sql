-- Migration 1200: Add per-API-key rate limiting column
-- Feature 202: API Key Identity Fix

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rate_limit_per_hour INTEGER;

COMMENT ON COLUMN api_keys.rate_limit_per_hour IS 'Optional per-key rate limit (requests per hour). NULL or 0 = no per-key limit.';
