-- F-IDEMPOTENCY: HTTP-level idempotency support
-- Stores request/response pairs for idempotent replay

CREATE TABLE idempotent_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    idempotency_key VARCHAR(256) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,  -- SHA-256 hex of request body
    endpoint VARCHAR(255) NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    response_status SMALLINT,
    response_body BYTEA,
    response_headers JSONB,
    state VARCHAR(20) NOT NULL DEFAULT 'processing',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT valid_state CHECK (state IN ('processing', 'completed', 'failed'))
);

-- Unique per tenant + key (allows same key across tenants)
CREATE UNIQUE INDEX idx_idempotent_requests_key
    ON idempotent_requests(tenant_id, idempotency_key);

-- For cleanup job - only query completed/failed entries
CREATE INDEX idx_idempotent_requests_expires
    ON idempotent_requests(expires_at)
    WHERE state IN ('completed', 'failed');

-- For finding stale processing entries (lock timeout)
CREATE INDEX idx_idempotent_requests_processing
    ON idempotent_requests(created_at)
    WHERE state = 'processing';

-- RLS
ALTER TABLE idempotent_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY idempotent_requests_tenant_isolation
    ON idempotent_requests
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

COMMENT ON TABLE idempotent_requests IS 'Stores idempotent request/response pairs for HTTP replay';
COMMENT ON COLUMN idempotent_requests.idempotency_key IS 'Client-provided unique key (1-256 chars)';
COMMENT ON COLUMN idempotent_requests.request_hash IS 'SHA-256 of request body to detect payload mismatch';
COMMENT ON COLUMN idempotent_requests.state IS 'processing = in flight, completed = cacheable, failed = error cached';
