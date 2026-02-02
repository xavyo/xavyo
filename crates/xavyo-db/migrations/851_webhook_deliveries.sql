-- F085: Webhook Deliveries table
-- Records of individual delivery attempts

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subscription_id   UUID NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_id          UUID NOT NULL,
    event_type        VARCHAR(100) NOT NULL,
    status            VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempt_number    INTEGER NOT NULL DEFAULT 1,
    max_attempts      INTEGER NOT NULL DEFAULT 6,
    next_attempt_at   TIMESTAMPTZ,
    request_payload   JSONB NOT NULL,
    request_headers   JSONB,
    response_code     SMALLINT,
    response_body     TEXT,
    error_message     TEXT,
    latency_ms        INTEGER,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at      TIMESTAMPTZ,

    CONSTRAINT chk_wd_status_valid CHECK (status IN ('pending', 'success', 'failed', 'timeout', 'abandoned')),
    CONSTRAINT chk_wd_attempt_number_positive CHECK (attempt_number >= 1),
    CONSTRAINT chk_wd_attempt_within_max CHECK (attempt_number <= max_attempts)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant_sub
    ON webhook_deliveries (tenant_id, subscription_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending
    ON webhook_deliveries (status, next_attempt_at)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant_sub_created
    ON webhook_deliveries (tenant_id, subscription_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event_id
    ON webhook_deliveries (tenant_id, event_id);

-- Row-Level Security
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_deliveries_tenant_isolation
    ON webhook_deliveries
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
