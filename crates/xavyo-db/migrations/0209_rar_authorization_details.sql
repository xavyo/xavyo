-- Migration: Rich Authorization Requests (RFC 9396) — authorization_details
--
-- Adds an optional `authorization_details` JSONB column to the two stores that
-- carry an authorization request through the auth-code flow:
--   par_requests        — details pushed at POST /oauth/par
--   authorization_codes — details granted at /authorize, redeemed at /token
--
-- The value is the RFC 9396 JSON array of typed objects (v1: `tool_access`),
-- validated/parsed in application code (xavyo-auth::rar) before storage. NULL ⇒
-- the request carried only coarse `scope`. Both tables already enforce
-- tenant-scoped RLS, so the new column inherits that isolation.

ALTER TABLE par_requests
    ADD COLUMN IF NOT EXISTS authorization_details JSONB;

ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS authorization_details JSONB;

COMMENT ON COLUMN par_requests.authorization_details IS 'RFC 9396 authorization_details (JSON array of typed grants); NULL = scope-only request';
COMMENT ON COLUMN authorization_codes.authorization_details IS 'RFC 9396 authorization_details granted at /authorize, embedded in the access token at /token; NULL = scope-only';
