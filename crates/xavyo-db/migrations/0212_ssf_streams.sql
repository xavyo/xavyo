-- Migration: Shared Signals Framework streams + subjects (OpenID SSF 1.0 §8)
--
-- xavyo acts as an SSF Transmitter. A `stream` is a receiver's registration to
-- receive Security Event Tokens (SETs): where to deliver (push endpoint), which
-- CAEP events, and its status. `ssf_subjects` are the subjects a receiver has
-- asked to be notified about on a stream (add/remove subject endpoints).
-- Both are tenant-scoped (RLS) — a SET is only ever delivered to streams in the
-- originating tenant.

CREATE TABLE IF NOT EXISTS ssf_streams (
    stream_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Receiver audience (SET `aud`).
    aud TEXT NOT NULL,
    -- Delivery method URN (v1: push, urn:ietf:rfc:8935).
    delivery_method TEXT NOT NULL DEFAULT 'urn:ietf:rfc:8935',
    -- Push delivery endpoint the SETs are POSTed to.
    endpoint_url TEXT NOT NULL,
    -- Optional bearer token to present to the receiver endpoint when delivering.
    delivery_authorization_header TEXT,
    -- CAEP event type URIs the receiver requested / the transmitter will deliver.
    events_requested TEXT[] NOT NULL DEFAULT '{}',
    events_delivered TEXT[] NOT NULL DEFAULT '{}',
    -- Stream status (SSF §8.1.2): enabled | paused | disabled.
    status TEXT NOT NULL DEFAULT 'enabled',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ssf_streams_status_valid
        CHECK (status IN ('enabled', 'paused', 'disabled'))
);

CREATE INDEX IF NOT EXISTS idx_ssf_streams_tenant_id ON ssf_streams(tenant_id);

CREATE TABLE IF NOT EXISTS ssf_subjects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id UUID NOT NULL REFERENCES ssf_streams(stream_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The RFC 9493 Subject Identifier (stored as its JSON object).
    subject JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ssf_subjects_stream_id ON ssf_subjects(stream_id);
CREATE INDEX IF NOT EXISTS idx_ssf_subjects_tenant_id ON ssf_subjects(tenant_id);

-- Row-Level Security: tenant isolation on both tables.
ALTER TABLE ssf_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_streams FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_policy ON ssf_streams;
CREATE POLICY tenant_isolation_policy ON ssf_streams
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

ALTER TABLE ssf_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_subjects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_policy ON ssf_subjects;
CREATE POLICY tenant_isolation_policy ON ssf_subjects
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE ssf_streams IS 'OpenID Shared Signals Framework streams (xavyo as Transmitter); tenant-scoped';
COMMENT ON TABLE ssf_subjects IS 'Subjects registered to an SSF stream for event delivery';
