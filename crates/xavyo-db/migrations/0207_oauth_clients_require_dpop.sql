-- Migration: per-client DPoP enforcement flag (RFC 9449)
--
-- When true, the token endpoint REQUIRES a valid DPoP proof for this client and
-- issues sender-constrained (cnf.jkt) access tokens. Default false preserves
-- existing bearer-token behaviour; the NHI/agent-provisioning path sets it true
-- so agent tokens are proof-of-possession by default.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS require_dpop BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN oauth_clients.require_dpop
    IS 'When true, this client must present a DPoP proof and receives sender-constrained tokens (RFC 9449)';
