-- F064: Semi-manual Resources
-- Migration for ticketing integration and manual provisioning tasks

-- =============================================================================
-- ENUM TYPES
-- =============================================================================

-- Ticketing system type
CREATE TYPE gov_ticketing_type AS ENUM (
    'service_now',
    'jira',
    'webhook'
);

-- Provisioning operation type
CREATE TYPE gov_provisioning_operation AS ENUM (
    'grant',
    'revoke',
    'modify'
);

-- Manual task status
CREATE TYPE gov_manual_task_status AS ENUM (
    'pending',
    'pending_ticket',
    'ticket_created',
    'ticket_failed',
    'in_progress',
    'partially_completed',
    'completed',
    'rejected',
    'cancelled',
    'failed_permanent'
);

-- External ticket status category
CREATE TYPE gov_ticket_status_category AS ENUM (
    'open',
    'in_progress',
    'pending',
    'resolved',
    'closed',
    'rejected'
);

-- =============================================================================
-- TICKETING CONFIGURATIONS
-- =============================================================================

CREATE TABLE gov_ticketing_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    ticketing_type gov_ticketing_type NOT NULL,
    endpoint_url TEXT NOT NULL,
    credentials BYTEA NOT NULL, -- Encrypted credentials
    field_mappings JSONB,
    default_assignee VARCHAR(255),
    default_assignment_group VARCHAR(255),
    project_key VARCHAR(100), -- Jira project
    issue_type VARCHAR(100), -- Jira issue type
    polling_interval_seconds INTEGER NOT NULL DEFAULT 300,
    webhook_callback_secret BYTEA, -- Encrypted webhook secret
    status_field_mapping JSONB,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ticketing_configs_tenant ON gov_ticketing_configurations(tenant_id, is_active);

-- RLS for ticketing configurations
ALTER TABLE gov_ticketing_configurations ENABLE ROW LEVEL SECURITY;

CREATE POLICY ticketing_configs_tenant_isolation ON gov_ticketing_configurations
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- =============================================================================
-- SLA POLICIES
-- =============================================================================

CREATE TABLE gov_sla_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_duration_seconds INTEGER NOT NULL,
    warning_threshold_percent INTEGER NOT NULL DEFAULT 75,
    escalation_contacts JSONB,
    breach_notification_enabled BOOLEAN NOT NULL DEFAULT true,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT sla_target_duration_positive CHECK (target_duration_seconds > 0),
    CONSTRAINT sla_warning_threshold_valid CHECK (warning_threshold_percent > 0 AND warning_threshold_percent < 100)
);

CREATE INDEX idx_sla_policies_tenant ON gov_sla_policies(tenant_id, is_active);

-- RLS for SLA policies
ALTER TABLE gov_sla_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY sla_policies_tenant_isolation ON gov_sla_policies
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- =============================================================================
-- EXTEND GOV_APPLICATIONS WITH SEMI-MANUAL FIELDS
-- =============================================================================

ALTER TABLE gov_applications
    ADD COLUMN IF NOT EXISTS is_semi_manual BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS ticketing_config_id UUID REFERENCES gov_ticketing_configurations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS sla_policy_id UUID REFERENCES gov_sla_policies(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS requires_approval_before_ticket BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX idx_applications_semi_manual ON gov_applications(tenant_id, is_semi_manual) WHERE is_semi_manual = true;

-- =============================================================================
-- MANUAL PROVISIONING TASKS
-- =============================================================================

CREATE TABLE gov_manual_provisioning_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    assignment_id UUID NOT NULL REFERENCES gov_entitlement_assignments(id) ON DELETE CASCADE,
    application_id UUID NOT NULL REFERENCES gov_applications(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    entitlement_id UUID NOT NULL REFERENCES gov_entitlements(id) ON DELETE CASCADE,
    operation_type gov_provisioning_operation NOT NULL,
    status gov_manual_task_status NOT NULL DEFAULT 'pending',
    external_ticket_id UUID, -- Set after ticket creation
    sla_deadline TIMESTAMPTZ,
    sla_warning_sent BOOLEAN NOT NULL DEFAULT false,
    sla_breached BOOLEAN NOT NULL DEFAULT false,
    assignee_id UUID,
    notes TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Performance indexes
CREATE INDEX idx_manual_tasks_tenant_status ON gov_manual_provisioning_tasks(tenant_id, status);
CREATE INDEX idx_manual_tasks_pending_retry ON gov_manual_provisioning_tasks(status, next_retry_at)
    WHERE status IN ('pending', 'pending_ticket', 'ticket_failed');
CREATE INDEX idx_manual_tasks_sla_deadline ON gov_manual_provisioning_tasks(sla_deadline)
    WHERE status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent');
CREATE INDEX idx_manual_tasks_assignment ON gov_manual_provisioning_tasks(assignment_id);
CREATE INDEX idx_manual_tasks_application ON gov_manual_provisioning_tasks(application_id);
CREATE INDEX idx_manual_tasks_user ON gov_manual_provisioning_tasks(user_id);

-- RLS for manual tasks
ALTER TABLE gov_manual_provisioning_tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY manual_tasks_tenant_isolation ON gov_manual_provisioning_tasks
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- =============================================================================
-- EXTERNAL TICKETS
-- =============================================================================

CREATE TABLE gov_external_tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id UUID NOT NULL UNIQUE REFERENCES gov_manual_provisioning_tasks(id) ON DELETE CASCADE,
    ticketing_config_id UUID NOT NULL REFERENCES gov_ticketing_configurations(id) ON DELETE CASCADE,
    external_reference VARCHAR(255) NOT NULL, -- ServiceNow sys_id or Jira key
    external_url TEXT,
    external_status VARCHAR(100),
    status_category gov_ticket_status_category NOT NULL DEFAULT 'open',
    created_externally_at TIMESTAMPTZ,
    last_synced_at TIMESTAMPTZ,
    sync_error TEXT,
    raw_response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_external_tickets_task ON gov_external_tickets(task_id);
CREATE INDEX idx_external_tickets_sync ON gov_external_tickets(last_synced_at)
    WHERE status_category NOT IN ('resolved', 'closed', 'rejected');
CREATE INDEX idx_external_tickets_reference ON gov_external_tickets(tenant_id, ticketing_config_id, external_reference);

-- RLS for external tickets
ALTER TABLE gov_external_tickets ENABLE ROW LEVEL SECURITY;

CREATE POLICY external_tickets_tenant_isolation ON gov_external_tickets
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- Add foreign key constraint after table creation
ALTER TABLE gov_manual_provisioning_tasks
    ADD CONSTRAINT fk_manual_tasks_external_ticket
    FOREIGN KEY (external_ticket_id) REFERENCES gov_external_tickets(id) ON DELETE SET NULL;

-- =============================================================================
-- MANUAL TASK AUDIT EVENTS
-- =============================================================================

CREATE TABLE gov_manual_task_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES gov_manual_provisioning_tasks(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    actor_id UUID,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_task_audit_task ON gov_manual_task_audit_events(task_id);
CREATE INDEX idx_task_audit_tenant_time ON gov_manual_task_audit_events(tenant_id, created_at DESC);

-- RLS for audit events
ALTER TABLE gov_manual_task_audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY task_audit_tenant_isolation ON gov_manual_task_audit_events
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = '' THEN false
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- =============================================================================
-- TRIGGERS FOR UPDATED_AT
-- =============================================================================

CREATE TRIGGER update_ticketing_configs_updated_at
    BEFORE UPDATE ON gov_ticketing_configurations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sla_policies_updated_at
    BEFORE UPDATE ON gov_sla_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_manual_tasks_updated_at
    BEFORE UPDATE ON gov_manual_provisioning_tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_external_tickets_updated_at
    BEFORE UPDATE ON gov_external_tickets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
