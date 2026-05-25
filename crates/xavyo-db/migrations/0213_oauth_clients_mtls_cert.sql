-- Migration: mTLS client authentication (RFC 8705 self_signed_tls_client_auth)
--
-- The SHA-256 thumbprint (x5t#S256) of the client's registered mTLS certificate.
-- When set, the client may authenticate at the token/PAR endpoints by presenting
-- that certificate (the TLS-terminating gateway forwards its thumbprint) instead
-- of a client_secret / private_key_jwt. NULL ⇒ the client does not use mTLS auth.

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS tls_client_cert_thumbprint TEXT;

COMMENT ON COLUMN oauth_clients.tls_client_cert_thumbprint
    IS 'x5t#S256 of the client''s registered mTLS certificate for self_signed_tls_client_auth (RFC 8705); NULL = not used';
