-- F-029: Webhook Circuit Breaker State Table
-- Stores circuit breaker state for webhook subscriptions to enable
-- recovery after service restarts and persistence across instances.

CREATE TABLE IF NOT EXISTS webhook_circuit_breaker_state (
    subscription_id     UUID PRIMARY KEY REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    state               VARCHAR(20) NOT NULL DEFAULT 'closed',
    failure_count       INTEGER NOT NULL DEFAULT 0,
    last_failure_at     TIMESTAMPTZ,
    last_success_at     TIMESTAMPTZ,
    opened_at           TIMESTAMPTZ,
    recent_failures     JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_cb_state_valid CHECK (state IN ('closed', 'open', 'half_open')),
    CONSTRAINT chk_cb_failure_count_non_negative CHECK (failure_count >= 0)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_webhook_cb_state_tenant_id
    ON webhook_circuit_breaker_state (tenant_id);

CREATE INDEX IF NOT EXISTS idx_webhook_cb_state_tenant_state
    ON webhook_circuit_breaker_state (tenant_id, state);

-- Row-Level Security
ALTER TABLE webhook_circuit_breaker_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY webhook_circuit_breaker_state_tenant_isolation
    ON webhook_circuit_breaker_state
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_webhook_circuit_breaker_state_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_webhook_circuit_breaker_state_updated_at
    BEFORE UPDATE ON webhook_circuit_breaker_state
    FOR EACH ROW
    EXECUTE FUNCTION update_webhook_circuit_breaker_state_updated_at();
