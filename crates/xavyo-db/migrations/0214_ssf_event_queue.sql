-- Migration: Shared Signals Framework poll-based delivery (RFC 8936)
--
-- For poll-delivery streams (delivery_method = urn:ietf:rfc:8936), xavyo does
-- not push SETs to a receiver endpoint — it queues them here and the receiver
-- pulls them via POST /ssf/poll, then acknowledges (which deletes them).
--
-- The polling receiver authenticates with a per-stream bearer token. Because
-- the poll request arrives with no tenant context yet, the token is resolved
-- against `ssf_poll_tokens` (keyed by the token's SHA-256 hash) to recover the
-- stream + tenant; the handler then sets the tenant context before touching any
-- RLS-protected table. The lookup table holds no secrets beyond the hash and is
-- only reachable by presenting the exact high-entropy token, so it is not
-- RLS-scoped (it is the thing that establishes which tenant a poll belongs to).

-- Per-stream poll bearer-token resolution (token hash -> stream + tenant).
CREATE TABLE IF NOT EXISTS ssf_poll_tokens (
    -- SHA-256 hex of the per-stream poll bearer token.
    token_hash TEXT PRIMARY KEY,
    stream_id UUID NOT NULL REFERENCES ssf_streams(stream_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ssf_poll_tokens_stream
    ON ssf_poll_tokens(stream_id);

CREATE TABLE IF NOT EXISTS ssf_event_queue (
    -- The SET's jti — also the acknowledgement key (RFC 8936 §2.4).
    jti TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stream_id UUID NOT NULL REFERENCES ssf_streams(stream_id) ON DELETE CASCADE,
    -- The signed compact JWS, served verbatim to the polling receiver.
    set_jwt TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- FIFO poll: oldest-first within a stream.
CREATE INDEX IF NOT EXISTS idx_ssf_event_queue_stream
    ON ssf_event_queue(tenant_id, stream_id, created_at);

-- Row-Level Security: tenant isolation on the queue (same shape as ssf_streams).
-- (ssf_poll_tokens is intentionally NOT RLS-scoped — it is the pre-tenant-context
--  credential-resolution table, only reachable with the exact token hash.)
ALTER TABLE ssf_event_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_event_queue FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_policy ON ssf_event_queue;
CREATE POLICY tenant_isolation_policy ON ssf_event_queue
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE ssf_event_queue IS 'Queued Security Event Tokens for poll-based delivery (RFC 8936); tenant-scoped, served until acked';
COMMENT ON TABLE ssf_poll_tokens IS 'Per-stream poll bearer-token resolution (token hash -> stream + tenant); pre-tenant-context credential lookup, not RLS-scoped';
