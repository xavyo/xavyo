-- Migration: 042_compliance_reporting
-- Feature: F042 - Compliance Reporting
-- Description: Tables for report templates, generated reports, and report schedules

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

-- Report template types
DO $$ BEGIN
    CREATE TYPE gov_report_template_type AS ENUM (
        'access_review',
        'sod_violations',
        'certification_status',
        'user_access',
        'audit_trail'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Compliance standards
DO $$ BEGIN
    CREATE TYPE gov_compliance_standard AS ENUM (
        'sox',
        'gdpr',
        'hipaa',
        'custom'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Report generation status
DO $$ BEGIN
    CREATE TYPE gov_report_status AS ENUM (
        'pending',
        'generating',
        'completed',
        'failed'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Schedule frequency
DO $$ BEGIN
    CREATE TYPE gov_schedule_frequency AS ENUM (
        'daily',
        'weekly',
        'monthly'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Schedule status
DO $$ BEGIN
    CREATE TYPE gov_schedule_status AS ENUM (
        'active',
        'paused',
        'disabled'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Output format
DO $$ BEGIN
    CREATE TYPE gov_output_format AS ENUM (
        'json',
        'csv'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Template status
DO $$ BEGIN
    CREATE TYPE gov_template_status AS ENUM (
        'active',
        'archived'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- TABLES
-- ============================================================================

-- Report templates table
CREATE TABLE IF NOT EXISTS gov_report_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID, -- NULL for system templates
    name VARCHAR(255) NOT NULL,
    description TEXT,
    template_type gov_report_template_type NOT NULL,
    compliance_standard gov_compliance_standard,
    definition JSONB NOT NULL DEFAULT '{}',
    is_system BOOLEAN NOT NULL DEFAULT false,
    cloned_from UUID REFERENCES gov_report_templates(id) ON DELETE SET NULL,
    status gov_template_status NOT NULL DEFAULT 'active',
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_system_template_no_tenant CHECK (
        (is_system = true AND tenant_id IS NULL) OR
        (is_system = false AND tenant_id IS NOT NULL)
    ),
    CONSTRAINT uq_template_name_per_tenant UNIQUE NULLS NOT DISTINCT (tenant_id, name)
);

-- Generated reports table
CREATE TABLE IF NOT EXISTS gov_generated_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    template_id UUID NOT NULL REFERENCES gov_report_templates(id) ON DELETE RESTRICT,
    template_snapshot JSONB NOT NULL,
    name VARCHAR(255) NOT NULL,
    status gov_report_status NOT NULL DEFAULT 'pending',
    parameters JSONB NOT NULL DEFAULT '{}',
    output_data JSONB,
    output_file_path VARCHAR(500),
    output_format gov_output_format NOT NULL,
    record_count INTEGER,
    file_size_bytes BIGINT,
    error_message TEXT,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    generated_by UUID NOT NULL,
    schedule_id UUID,
    retention_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_progress_range CHECK (progress_percent >= 0 AND progress_percent <= 100),
    CONSTRAINT chk_record_count_non_negative CHECK (record_count IS NULL OR record_count >= 0),
    CONSTRAINT chk_file_size_non_negative CHECK (file_size_bytes IS NULL OR file_size_bytes >= 0),
    CONSTRAINT chk_completed_has_output CHECK (
        status != 'completed' OR
        (output_data IS NOT NULL OR output_file_path IS NOT NULL)
    )
);

-- Report schedules table
CREATE TABLE IF NOT EXISTS gov_report_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    template_id UUID NOT NULL REFERENCES gov_report_templates(id) ON DELETE RESTRICT,
    name VARCHAR(255) NOT NULL,
    frequency gov_schedule_frequency NOT NULL,
    schedule_hour INTEGER NOT NULL,
    schedule_day_of_week INTEGER,
    schedule_day_of_month INTEGER,
    parameters JSONB NOT NULL DEFAULT '{}',
    recipients JSONB NOT NULL DEFAULT '[]',
    output_format gov_output_format NOT NULL DEFAULT 'json',
    status gov_schedule_status NOT NULL DEFAULT 'active',
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_schedule_hour CHECK (schedule_hour >= 0 AND schedule_hour <= 23),
    CONSTRAINT chk_day_of_week CHECK (
        schedule_day_of_week IS NULL OR
        (schedule_day_of_week >= 0 AND schedule_day_of_week <= 6)
    ),
    CONSTRAINT chk_day_of_month CHECK (
        schedule_day_of_month IS NULL OR
        (schedule_day_of_month >= 1 AND schedule_day_of_month <= 31)
    ),
    CONSTRAINT chk_consecutive_failures_non_negative CHECK (consecutive_failures >= 0),
    CONSTRAINT chk_weekly_requires_day_of_week CHECK (
        frequency != 'weekly' OR schedule_day_of_week IS NOT NULL
    ),
    CONSTRAINT chk_monthly_requires_day_of_month CHECK (
        frequency != 'monthly' OR schedule_day_of_month IS NOT NULL
    ),
    CONSTRAINT uq_schedule_name_per_tenant UNIQUE (tenant_id, name)
);

-- Add foreign key for schedule_id in generated_reports
ALTER TABLE gov_generated_reports
    ADD CONSTRAINT fk_generated_reports_schedule
    FOREIGN KEY (schedule_id) REFERENCES gov_report_schedules(id) ON DELETE SET NULL;

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Report templates indexes
CREATE INDEX IF NOT EXISTS idx_gov_report_templates_tenant_id ON gov_report_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_report_templates_type ON gov_report_templates(template_type);
CREATE INDEX IF NOT EXISTS idx_gov_report_templates_standard ON gov_report_templates(compliance_standard);
CREATE INDEX IF NOT EXISTS idx_gov_report_templates_is_system ON gov_report_templates(is_system);
CREATE INDEX IF NOT EXISTS idx_gov_report_templates_status ON gov_report_templates(status);

-- Generated reports indexes
CREATE INDEX IF NOT EXISTS idx_gov_generated_reports_tenant_id ON gov_generated_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_generated_reports_template_id ON gov_generated_reports(template_id);
CREATE INDEX IF NOT EXISTS idx_gov_generated_reports_status ON gov_generated_reports(status);
CREATE INDEX IF NOT EXISTS idx_gov_generated_reports_generated_by ON gov_generated_reports(generated_by);
CREATE INDEX IF NOT EXISTS idx_gov_generated_reports_schedule_id ON gov_generated_reports(schedule_id);
CREATE INDEX IF NOT EXISTS idx_gov_generated_reports_retention ON gov_generated_reports(retention_until) WHERE status = 'completed';
CREATE INDEX IF NOT EXISTS idx_gov_generated_reports_created_at ON gov_generated_reports(tenant_id, created_at DESC);

-- Report schedules indexes
CREATE INDEX IF NOT EXISTS idx_gov_report_schedules_tenant_id ON gov_report_schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_report_schedules_template_id ON gov_report_schedules(template_id);
CREATE INDEX IF NOT EXISTS idx_gov_report_schedules_next_run ON gov_report_schedules(next_run_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_gov_report_schedules_status ON gov_report_schedules(status);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE gov_report_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_generated_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_report_schedules ENABLE ROW LEVEL SECURITY;

-- RLS policies for gov_report_templates
-- Allow access to system templates (tenant_id IS NULL) and tenant-specific templates
DROP POLICY IF EXISTS gov_report_templates_tenant_isolation ON gov_report_templates;
CREATE POLICY gov_report_templates_tenant_isolation ON gov_report_templates
    FOR ALL
    USING (
        tenant_id IS NULL OR
        tenant_id = current_setting('app.current_tenant', true)::uuid
    )
    WITH CHECK (
        tenant_id IS NULL OR
        tenant_id = current_setting('app.current_tenant', true)::uuid
    );

-- RLS policies for gov_generated_reports
DROP POLICY IF EXISTS gov_generated_reports_tenant_isolation ON gov_generated_reports;
CREATE POLICY gov_generated_reports_tenant_isolation ON gov_generated_reports
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_report_schedules
DROP POLICY IF EXISTS gov_report_schedules_tenant_isolation ON gov_report_schedules;
CREATE POLICY gov_report_schedules_tenant_isolation ON gov_report_schedules
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Reuse update_updated_at_column function (created in earlier migrations)
-- Apply updated_at triggers
DROP TRIGGER IF EXISTS update_gov_report_templates_updated_at ON gov_report_templates;
CREATE TRIGGER update_gov_report_templates_updated_at
    BEFORE UPDATE ON gov_report_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_gov_report_schedules_updated_at ON gov_report_schedules;
CREATE TRIGGER update_gov_report_schedules_updated_at
    BEFORE UPDATE ON gov_report_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger to enforce immutability on generated reports (prevent update of output_data and template_snapshot)
CREATE OR REPLACE FUNCTION enforce_generated_report_immutability()
RETURNS TRIGGER AS $$
BEGIN
    -- Allow status updates and progress tracking
    IF OLD.status IN ('pending', 'generating') THEN
        -- During generation, allow updates
        RETURN NEW;
    END IF;

    -- After completion, prevent changes to critical fields
    IF OLD.status IN ('completed', 'failed') THEN
        IF NEW.output_data IS DISTINCT FROM OLD.output_data THEN
            RAISE EXCEPTION 'Cannot modify output_data of completed/failed report';
        END IF;
        IF NEW.template_snapshot IS DISTINCT FROM OLD.template_snapshot THEN
            RAISE EXCEPTION 'Cannot modify template_snapshot of completed/failed report';
        END IF;
        IF NEW.parameters IS DISTINCT FROM OLD.parameters THEN
            RAISE EXCEPTION 'Cannot modify parameters of completed/failed report';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS enforce_gov_generated_reports_immutability ON gov_generated_reports;
CREATE TRIGGER enforce_gov_generated_reports_immutability
    BEFORE UPDATE ON gov_generated_reports
    FOR EACH ROW
    EXECUTE FUNCTION enforce_generated_report_immutability();

-- ============================================================================
-- SEED DATA: System Templates
-- ============================================================================

-- SOX Templates
INSERT INTO gov_report_templates (id, tenant_id, name, description, template_type, compliance_standard, definition, is_system, created_at, updated_at)
VALUES
    -- SOX Access Review
    (
        '550e8400-e29b-41d4-a716-446655440001',
        NULL,
        'SOX Access Review',
        'Sarbanes-Oxley access review report showing user entitlements, approval dates, and certification status',
        'access_review',
        'sox',
        '{
            "data_sources": ["entitlements", "assignments", "users", "certifications"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true},
                {"field": "department", "type": "select", "options": "dynamic", "required": false},
                {"field": "application_id", "type": "select", "options": "dynamic", "required": false}
            ],
            "columns": [
                {"field": "user_email", "label": "User Email", "sortable": true},
                {"field": "user_name", "label": "User Name", "sortable": true},
                {"field": "department", "label": "Department", "sortable": true},
                {"field": "entitlement_name", "label": "Entitlement", "sortable": true},
                {"field": "application_name", "label": "Application", "sortable": true},
                {"field": "risk_level", "label": "Risk Level", "sortable": true},
                {"field": "assigned_at", "label": "Assigned Date", "sortable": true},
                {"field": "approved_by", "label": "Approved By", "sortable": false},
                {"field": "certification_status", "label": "Certified", "sortable": true},
                {"field": "last_certified_at", "label": "Last Certified", "sortable": true}
            ],
            "grouping": ["application_name"],
            "default_sort": {"field": "user_email", "direction": "asc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- SOX SoD Violations
    (
        '550e8400-e29b-41d4-a716-446655440002',
        NULL,
        'SOX SoD Violations',
        'Sarbanes-Oxley separation of duties violations report with risk analysis',
        'sod_violations',
        'sox',
        '{
            "data_sources": ["sod_violations", "sod_rules", "users", "exemptions"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true},
                {"field": "severity", "type": "select", "options": ["high", "medium", "low"], "required": false},
                {"field": "status", "type": "select", "options": ["open", "remediated", "exempted"], "required": false}
            ],
            "columns": [
                {"field": "user_email", "label": "User Email", "sortable": true},
                {"field": "user_name", "label": "User Name", "sortable": true},
                {"field": "rule_name", "label": "SoD Rule", "sortable": true},
                {"field": "severity", "label": "Severity", "sortable": true},
                {"field": "conflicting_entitlements", "label": "Conflicting Access", "sortable": false},
                {"field": "detected_at", "label": "Detected Date", "sortable": true},
                {"field": "status", "label": "Status", "sortable": true},
                {"field": "exemption_reason", "label": "Exemption Reason", "sortable": false},
                {"field": "remediation_date", "label": "Remediated Date", "sortable": true}
            ],
            "grouping": ["severity"],
            "default_sort": {"field": "detected_at", "direction": "desc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- SOX Certification Status
    (
        '550e8400-e29b-41d4-a716-446655440003',
        NULL,
        'SOX Certification Status',
        'Sarbanes-Oxley certification campaign progress and decision summary',
        'certification_status',
        'sox',
        '{
            "data_sources": ["certification_campaigns", "certification_items", "certification_decisions"],
            "filters": [
                {"field": "campaign_id", "type": "select", "options": "dynamic", "required": false},
                {"field": "status", "type": "select", "options": ["pending", "in_progress", "completed"], "required": false}
            ],
            "columns": [
                {"field": "campaign_name", "label": "Campaign", "sortable": true},
                {"field": "reviewer_email", "label": "Reviewer", "sortable": true},
                {"field": "total_items", "label": "Total Items", "sortable": true},
                {"field": "certified_count", "label": "Certified", "sortable": true},
                {"field": "revoked_count", "label": "Revoked", "sortable": true},
                {"field": "pending_count", "label": "Pending", "sortable": true},
                {"field": "completion_percent", "label": "% Complete", "sortable": true},
                {"field": "due_date", "label": "Due Date", "sortable": true},
                {"field": "status", "label": "Status", "sortable": true}
            ],
            "grouping": ["campaign_name"],
            "default_sort": {"field": "due_date", "direction": "asc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- GDPR Data Access
    (
        '550e8400-e29b-41d4-a716-446655440004',
        NULL,
        'GDPR Data Access',
        'GDPR personal data access report showing who accessed what data and when',
        'access_review',
        'gdpr',
        '{
            "data_sources": ["entitlements", "assignments", "users", "audit_logs"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true},
                {"field": "data_category", "type": "select", "options": ["personal", "sensitive", "special"], "required": false}
            ],
            "columns": [
                {"field": "user_email", "label": "Data Accessor", "sortable": true},
                {"field": "department", "label": "Department", "sortable": true},
                {"field": "data_category", "label": "Data Category", "sortable": true},
                {"field": "application_name", "label": "System", "sortable": true},
                {"field": "access_type", "label": "Access Type", "sortable": true},
                {"field": "legal_basis", "label": "Legal Basis", "sortable": false},
                {"field": "purpose", "label": "Purpose", "sortable": false},
                {"field": "granted_at", "label": "Access Granted", "sortable": true},
                {"field": "last_accessed", "label": "Last Accessed", "sortable": true}
            ],
            "grouping": ["data_category"],
            "default_sort": {"field": "user_email", "direction": "asc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- GDPR Processing Activities
    (
        '550e8400-e29b-41d4-a716-446655440005',
        NULL,
        'GDPR Processing Activities',
        'GDPR record of processing activities showing data flows and purposes',
        'audit_trail',
        'gdpr',
        '{
            "data_sources": ["applications", "entitlements", "assignments"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true}
            ],
            "columns": [
                {"field": "application_name", "label": "Processing System", "sortable": true},
                {"field": "data_categories", "label": "Data Categories", "sortable": false},
                {"field": "processing_purpose", "label": "Purpose", "sortable": false},
                {"field": "legal_basis", "label": "Legal Basis", "sortable": false},
                {"field": "data_subjects", "label": "Data Subjects", "sortable": false},
                {"field": "recipients", "label": "Recipients", "sortable": false},
                {"field": "retention_period", "label": "Retention", "sortable": false},
                {"field": "security_measures", "label": "Security Measures", "sortable": false}
            ],
            "grouping": [],
            "default_sort": {"field": "application_name", "direction": "asc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- GDPR Subject Rights
    (
        '550e8400-e29b-41d4-a716-446655440006',
        NULL,
        'GDPR Subject Rights',
        'GDPR data subject rights requests and fulfillment status',
        'audit_trail',
        'gdpr',
        '{
            "data_sources": ["audit_logs", "users"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true},
                {"field": "request_type", "type": "select", "options": ["access", "rectification", "erasure", "portability", "restriction"], "required": false}
            ],
            "columns": [
                {"field": "subject_email", "label": "Data Subject", "sortable": true},
                {"field": "request_type", "label": "Request Type", "sortable": true},
                {"field": "request_date", "label": "Request Date", "sortable": true},
                {"field": "status", "label": "Status", "sortable": true},
                {"field": "response_date", "label": "Response Date", "sortable": true},
                {"field": "response_days", "label": "Days to Respond", "sortable": true},
                {"field": "handled_by", "label": "Handled By", "sortable": false}
            ],
            "grouping": ["request_type"],
            "default_sort": {"field": "request_date", "direction": "desc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- HIPAA Access Audit
    (
        '550e8400-e29b-41d4-a716-446655440007',
        NULL,
        'HIPAA Access Audit',
        'HIPAA PHI access audit trail for compliance verification',
        'access_review',
        'hipaa',
        '{
            "data_sources": ["entitlements", "assignments", "users", "audit_logs"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true},
                {"field": "phi_category", "type": "select", "options": ["clinical", "billing", "administrative"], "required": false}
            ],
            "columns": [
                {"field": "user_email", "label": "Workforce Member", "sortable": true},
                {"field": "user_role", "label": "Role", "sortable": true},
                {"field": "department", "label": "Department", "sortable": true},
                {"field": "system_name", "label": "System", "sortable": true},
                {"field": "phi_category", "label": "PHI Category", "sortable": true},
                {"field": "access_level", "label": "Access Level", "sortable": true},
                {"field": "access_granted", "label": "Access Granted", "sortable": true},
                {"field": "last_access", "label": "Last Access", "sortable": true},
                {"field": "access_justified", "label": "Justified", "sortable": true}
            ],
            "grouping": ["system_name"],
            "default_sort": {"field": "user_email", "direction": "asc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- HIPAA Risk Assessment
    (
        '550e8400-e29b-41d4-a716-446655440008',
        NULL,
        'HIPAA Risk Assessment',
        'HIPAA security risk assessment report with risk scores and anomalies',
        'user_access',
        'hipaa',
        '{
            "data_sources": ["users", "risk_scores", "risk_events", "entitlements"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true},
                {"field": "risk_level", "type": "select", "options": ["critical", "high", "medium", "low"], "required": false}
            ],
            "columns": [
                {"field": "user_email", "label": "User", "sortable": true},
                {"field": "department", "label": "Department", "sortable": true},
                {"field": "risk_score", "label": "Risk Score", "sortable": true},
                {"field": "risk_level", "label": "Risk Level", "sortable": true},
                {"field": "phi_access_count", "label": "PHI Systems", "sortable": true},
                {"field": "anomaly_count", "label": "Anomalies", "sortable": true},
                {"field": "last_assessment", "label": "Last Assessment", "sortable": true},
                {"field": "risk_factors", "label": "Risk Factors", "sortable": false}
            ],
            "grouping": ["risk_level"],
            "default_sort": {"field": "risk_score", "direction": "desc"}
        }',
        true,
        NOW(),
        NOW()
    ),
    -- HIPAA Incidents
    (
        '550e8400-e29b-41d4-a716-446655440009',
        NULL,
        'HIPAA Incidents',
        'HIPAA security incidents, violations, and remediation tracking',
        'audit_trail',
        'hipaa',
        '{
            "data_sources": ["sod_violations", "orphan_detections", "risk_events"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true},
                {"field": "incident_type", "type": "select", "options": ["unauthorized_access", "policy_violation", "orphan_account", "sod_conflict"], "required": false}
            ],
            "columns": [
                {"field": "incident_date", "label": "Date", "sortable": true},
                {"field": "incident_type", "label": "Incident Type", "sortable": true},
                {"field": "affected_user", "label": "Affected User", "sortable": true},
                {"field": "description", "label": "Description", "sortable": false},
                {"field": "severity", "label": "Severity", "sortable": true},
                {"field": "status", "label": "Status", "sortable": true},
                {"field": "remediation_action", "label": "Remediation", "sortable": false},
                {"field": "remediated_by", "label": "Remediated By", "sortable": false},
                {"field": "remediation_date", "label": "Remediation Date", "sortable": true}
            ],
            "grouping": ["incident_type"],
            "default_sort": {"field": "incident_date", "direction": "desc"}
        }',
        true,
        NOW(),
        NOW()
    )
ON CONFLICT DO NOTHING;
