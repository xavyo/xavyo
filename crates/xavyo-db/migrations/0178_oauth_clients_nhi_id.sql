-- Add nhi_id to oauth_clients to bind an OAuth client to an NHI agent identity.
-- When set, client_credentials tokens use nhi_id as the subject (sub claim)
-- instead of the client_id, enabling NHI agents to obtain JWTs with their
-- NHI identity for delegation flows (RFC 8693 Token Exchange).

ALTER TABLE oauth_clients ADD COLUMN nhi_id UUID REFERENCES nhi_identities(id) ON DELETE SET NULL;

-- Index for looking up which client is bound to which NHI
CREATE INDEX idx_oauth_clients_nhi_id ON oauth_clients(nhi_id) WHERE nhi_id IS NOT NULL;
