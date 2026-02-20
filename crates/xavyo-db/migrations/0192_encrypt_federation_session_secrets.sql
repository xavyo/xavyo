-- Encrypt PKCE verifier and nonce at rest in federation sessions.
-- Existing sessions are ephemeral (10min TTL); safe to clear.
DELETE FROM federated_auth_sessions;

ALTER TABLE federated_auth_sessions
    ALTER COLUMN pkce_verifier TYPE BYTEA USING pkce_verifier::bytea,
    ALTER COLUMN nonce TYPE BYTEA USING nonce::bytea;
