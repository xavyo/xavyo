-- Migration: per-client FAPI 2.0 Security Profile opt-in flag
--
-- When true, this client must meet the FAPI 2.0 authorization-server obligations
-- (FAPI 2.0 Security Profile §5.3.2): authorization requests MUST use PAR
-- (RFC 9126) and tokens MUST be sender-constrained (DPoP, RFC 9449). The flag
-- implies require_dpop semantics at the token endpoint and PAR-mandatory at the
-- authorization endpoint. Default false preserves existing behaviour for
-- non-FAPI clients.
--
-- Full FAPI conformance additionally requires private_key_jwt / mTLS client
-- authentication (RFC 7523 / RFC 8705), tracked as a separate follow-up.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS fapi_profile BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN oauth_clients.fapi_profile
    IS 'When true, this client must use PAR (RFC 9126) and sender-constrained DPoP tokens (RFC 9449) per FAPI 2.0 Security Profile §5.3.2';
