-- Migration: 892_ai_tools
-- Feature: F089 - AI Agent Security Platform
-- Description: Create ai_tools table for MCP-style tool registry

-- Create ai_tools table
CREATE TABLE IF NOT EXISTS ai_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),

    -- Schema (JSON Schema for parameters)
    input_schema JSONB NOT NULL DEFAULT '{}',
    output_schema JSONB,

    -- Security Classification (OWASP ASI02)
    risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    max_calls_per_hour INTEGER,

    -- Provenance (OWASP ASI04)
    provider VARCHAR(255),
    provider_verified BOOLEAN NOT NULL DEFAULT false,
    checksum VARCHAR(64),

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT ai_tools_tenant_name_unique UNIQUE (tenant_id, name),
    CONSTRAINT ai_tools_risk_level_check CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT ai_tools_status_check CHECK (status IN ('active', 'inactive', 'deprecated'))
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_ai_tools_tenant ON ai_tools(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_tools_tenant_name ON ai_tools(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_ai_tools_tenant_status ON ai_tools(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_ai_tools_tenant_category ON ai_tools(tenant_id, category);
CREATE INDEX IF NOT EXISTS idx_ai_tools_tenant_risk ON ai_tools(tenant_id, risk_level);

-- Enable RLS
ALTER TABLE ai_tools ENABLE ROW LEVEL SECURITY;

-- RLS policies for tenant isolation
CREATE POLICY ai_tools_tenant_isolation_select ON ai_tools
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_tools_tenant_isolation_insert ON ai_tools
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_tools_tenant_isolation_update ON ai_tools
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

CREATE POLICY ai_tools_tenant_isolation_delete ON ai_tools
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Comments for documentation
COMMENT ON TABLE ai_tools IS 'Tool registry for MCP-style agent capabilities (F089)';
COMMENT ON COLUMN ai_tools.input_schema IS 'JSON Schema defining tool parameters (MCP compatible)';
COMMENT ON COLUMN ai_tools.output_schema IS 'Expected output schema for tool responses';
COMMENT ON COLUMN ai_tools.risk_level IS 'OWASP ASI02: Tool risk classification for authorization decisions';
COMMENT ON COLUMN ai_tools.provider IS 'Tool source: internal, mcp:<service>, external:<url>';
COMMENT ON COLUMN ai_tools.provider_verified IS 'OWASP ASI04: Whether provider provenance has been verified';
COMMENT ON COLUMN ai_tools.checksum IS 'SHA-256 checksum of tool definition for integrity verification';
