-- F-029: Webhook Dead Letter Queue Table
-- Stores webhooks that exhausted all retry attempts for manual
-- investigation and replay.

CREATE TABLE IF NOT EXISTS webhook_dlq (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subscription_id     UUID NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    subscription_url    VARCHAR(2000) NOT NULL,
    event_id            UUID NOT NULL,
    event_type          VARCHAR(255) NOT NULL,
    request_payload     JSONB NOT NULL,
    failure_reason      TEXT NOT NULL,
    last_response_code  SMALLINT,
    last_response_body  TEXT,
    attempt_history     JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    replayed_at         TIMESTAMPTZ,

    CONSTRAINT chk_dlq_subscription_url_not_empty CHECK (length(subscription_url) > 0),
    CONSTRAINT chk_dlq_event_type_not_empty CHECK (length(event_type) > 0),
    CONSTRAINT chk_dlq_failure_reason_not_empty CHECK (length(failure_reason) > 0)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant_id
    ON webhook_dlq (tenant_id);

CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant_subscription
    ON webhook_dlq (tenant_id, subscription_id);

CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant_event_type
    ON webhook_dlq (tenant_id, event_type);

CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant_created_at
    ON webhook_dlq (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_dlq_tenant_unreplayed
    ON webhook_dlq (tenant_id, subscription_id, created_at ASC)
    WHERE replayed_at IS NULL;

-- Row-Level Security
ALTER TABLE webhook_dlq ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_dlq_tenant_isolation
    ON webhook_dlq
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
