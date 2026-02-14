-- F085: Webhook Subscriptions table
-- Tenant-scoped webhook subscription configuration

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    url             VARCHAR(2000) NOT NULL,
    secret_encrypted TEXT,
    event_types     TEXT[] NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      UUID,

    CONSTRAINT chk_ws_url_not_empty CHECK (length(url) > 0),
    CONSTRAINT chk_ws_event_types_not_empty CHECK (array_length(event_types, 1) > 0),
    CONSTRAINT chk_ws_consecutive_failures_non_negative CHECK (consecutive_failures >= 0)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_tenant_id
    ON webhook_subscriptions (tenant_id);

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_tenant_enabled
    ON webhook_subscriptions (tenant_id, enabled);

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_tenant_event_types
    ON webhook_subscriptions USING GIN (event_types);

-- Row-Level Security
ALTER TABLE webhook_subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_subscriptions_tenant_isolation
    ON webhook_subscriptions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_webhook_subscriptions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_webhook_subscriptions_updated_at
    BEFORE UPDATE ON webhook_subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_webhook_subscriptions_updated_at();
