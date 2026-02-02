-- F073: Adaptive Risk-Based Authentication
-- Adds per-tenant enforcement policy configuration for risk-based login evaluation.

-- 1. Create enforcement_mode enum type
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'enforcement_mode') THEN
        CREATE TYPE enforcement_mode AS ENUM ('disabled', 'monitor', 'enforce');
    END IF;
END
$$;

-- 2. Create enforcement policies table (one row per tenant)
CREATE TABLE IF NOT EXISTS gov_risk_enforcement_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    enforcement_mode enforcement_mode NOT NULL DEFAULT 'disabled',
    fail_open       BOOLEAN NOT NULL DEFAULT true,
    impossible_travel_speed_kmh INTEGER NOT NULL DEFAULT 900,
    impossible_travel_enabled   BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_enforcement_policy_tenant UNIQUE (tenant_id),
    CONSTRAINT ck_travel_speed_range CHECK (impossible_travel_speed_kmh BETWEEN 100 AND 2000)
);

-- 3. Index on tenant_id for fast policy lookup
CREATE INDEX IF NOT EXISTS idx_gov_risk_enforcement_policies_tenant
    ON gov_risk_enforcement_policies(tenant_id);

-- 4. Row-Level Security
ALTER TABLE gov_risk_enforcement_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY gov_risk_enforcement_policies_tenant_isolation
    ON gov_risk_enforcement_policies
    USING (tenant_id = current_setting('app.current_tenant')::uuid);
