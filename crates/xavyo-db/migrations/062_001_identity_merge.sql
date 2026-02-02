-- Migration: 062_001_identity_merge
-- Feature: F062 - Identity Merge
-- Description: Duplicate detection and merge operations for identity management

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

-- Match type for correlation rules
DO $$ BEGIN
    CREATE TYPE gov_match_type AS ENUM (
        'exact',
        'fuzzy',
        'phonetic'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Fuzzy matching algorithm
DO $$ BEGIN
    CREATE TYPE gov_fuzzy_algorithm AS ENUM (
        'levenshtein',
        'jaro_winkler',
        'soundex'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Duplicate candidate status
DO $$ BEGIN
    CREATE TYPE gov_duplicate_status AS ENUM (
        'pending',
        'merged',
        'dismissed'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Merge operation status
DO $$ BEGIN
    CREATE TYPE gov_merge_operation_status AS ENUM (
        'in_progress',
        'completed',
        'failed',
        'cancelled'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Entitlement consolidation strategy
DO $$ BEGIN
    CREATE TYPE gov_entitlement_strategy AS ENUM (
        'union',
        'intersection',
        'manual'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- TABLES
-- ============================================================================

-- Correlation Rules: Defines how potential duplicates are detected
CREATE TABLE IF NOT EXISTS gov_correlation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    attribute VARCHAR(100) NOT NULL,
    match_type gov_match_type NOT NULL,
    algorithm gov_fuzzy_algorithm,
    threshold DECIMAL(3,2),
    weight DECIMAL(5,2) NOT NULL DEFAULT 1.0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_threshold_range CHECK (
        threshold IS NULL OR (threshold >= 0.00 AND threshold <= 1.00)
    ),
    CONSTRAINT chk_weight_positive CHECK (weight > 0),
    CONSTRAINT chk_fuzzy_requires_algorithm CHECK (
        match_type != 'fuzzy' OR algorithm IS NOT NULL
    ),
    CONSTRAINT chk_fuzzy_requires_threshold CHECK (
        match_type != 'fuzzy' OR threshold IS NOT NULL
    ),
    CONSTRAINT uq_correlation_rule_name UNIQUE (tenant_id, name)
);

-- Duplicate Candidates: Represents potential duplicate identity pairs
CREATE TABLE IF NOT EXISTS gov_duplicate_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    identity_a_id UUID NOT NULL,
    identity_b_id UUID NOT NULL,
    confidence_score DECIMAL(5,2) NOT NULL,
    status gov_duplicate_status NOT NULL DEFAULT 'pending',
    rule_matches JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dismissed_reason TEXT,
    dismissed_by UUID,
    dismissed_at TIMESTAMPTZ,

    CONSTRAINT chk_confidence_range CHECK (
        confidence_score >= 0.00 AND confidence_score <= 100.00
    ),
    CONSTRAINT chk_canonical_order CHECK (identity_a_id < identity_b_id),
    CONSTRAINT chk_dismissed_consistency CHECK (
        (status != 'dismissed') OR
        (dismissed_reason IS NOT NULL AND dismissed_by IS NOT NULL AND dismissed_at IS NOT NULL)
    ),
    CONSTRAINT uq_duplicate_pair UNIQUE (tenant_id, identity_a_id, identity_b_id)
);

-- Merge Operations: Records in-progress or completed merge operations
CREATE TABLE IF NOT EXISTS gov_merge_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    candidate_id UUID REFERENCES gov_duplicate_candidates(id),
    source_identity_id UUID NOT NULL,
    target_identity_id UUID NOT NULL,
    status gov_merge_operation_status NOT NULL DEFAULT 'in_progress',
    entitlement_strategy gov_entitlement_strategy NOT NULL,
    attribute_selections JSONB NOT NULL DEFAULT '{}',
    entitlement_selections JSONB,
    sod_check_result JSONB,
    sod_override_reason TEXT,
    operator_id UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,

    CONSTRAINT chk_source_target_different CHECK (source_identity_id != target_identity_id),
    CONSTRAINT chk_completed_has_timestamp CHECK (
        (status NOT IN ('completed', 'failed', 'cancelled')) OR completed_at IS NOT NULL
    ),
    CONSTRAINT chk_failed_has_error CHECK (
        status != 'failed' OR error_message IS NOT NULL
    )
);

-- Merge Audit: Immutable audit records for merge operations
CREATE TABLE IF NOT EXISTS gov_merge_audits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL REFERENCES gov_merge_operations(id),
    source_snapshot JSONB NOT NULL,
    target_snapshot JSONB NOT NULL,
    merged_snapshot JSONB NOT NULL,
    attribute_decisions JSONB NOT NULL,
    entitlement_decisions JSONB NOT NULL,
    sod_violations JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Prevent updates and deletes on audit records
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit records cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevent_merge_audit_update ON gov_merge_audits;
CREATE TRIGGER prevent_merge_audit_update
    BEFORE UPDATE ON gov_merge_audits
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

DROP TRIGGER IF EXISTS prevent_merge_audit_delete ON gov_merge_audits;
CREATE TRIGGER prevent_merge_audit_delete
    BEFORE DELETE ON gov_merge_audits
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- Archived Identities: Soft-deleted identities preserved for audit
CREATE TABLE IF NOT EXISTS gov_archived_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    original_user_id UUID NOT NULL,
    merge_operation_id UUID NOT NULL REFERENCES gov_merge_operations(id),
    snapshot JSONB NOT NULL,
    external_references JSONB NOT NULL DEFAULT '{}',
    archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_archived_original_user UNIQUE (tenant_id, original_user_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Correlation Rules indexes
CREATE INDEX IF NOT EXISTS idx_gov_correlation_rules_tenant ON gov_correlation_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_correlation_rules_active ON gov_correlation_rules(tenant_id, is_active)
    WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_gov_correlation_rules_priority ON gov_correlation_rules(tenant_id, priority DESC)
    WHERE is_active = true;

-- Duplicate Candidates indexes
CREATE INDEX IF NOT EXISTS idx_gov_duplicate_candidates_tenant_status ON gov_duplicate_candidates(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_duplicate_candidates_confidence ON gov_duplicate_candidates(tenant_id, confidence_score DESC)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_gov_duplicate_candidates_identities ON gov_duplicate_candidates(tenant_id, identity_a_id, identity_b_id);
CREATE INDEX IF NOT EXISTS idx_gov_duplicate_candidates_identity_a ON gov_duplicate_candidates(tenant_id, identity_a_id)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_gov_duplicate_candidates_identity_b ON gov_duplicate_candidates(tenant_id, identity_b_id)
    WHERE status = 'pending';

-- Merge Operations indexes
CREATE INDEX IF NOT EXISTS idx_gov_merge_operations_tenant_status ON gov_merge_operations(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_merge_operations_operator ON gov_merge_operations(tenant_id, operator_id);
CREATE INDEX IF NOT EXISTS idx_gov_merge_operations_source ON gov_merge_operations(tenant_id, source_identity_id);
CREATE INDEX IF NOT EXISTS idx_gov_merge_operations_target ON gov_merge_operations(tenant_id, target_identity_id);
CREATE INDEX IF NOT EXISTS idx_gov_merge_operations_in_progress ON gov_merge_operations(tenant_id, started_at)
    WHERE status = 'in_progress';

-- Merge Audit indexes
CREATE INDEX IF NOT EXISTS idx_gov_merge_audits_tenant ON gov_merge_audits(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_merge_audits_operation ON gov_merge_audits(operation_id);
CREATE INDEX IF NOT EXISTS idx_gov_merge_audits_created ON gov_merge_audits(tenant_id, created_at DESC);

-- Archived Identities indexes
CREATE INDEX IF NOT EXISTS idx_gov_archived_identities_tenant ON gov_archived_identities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gov_archived_identities_original ON gov_archived_identities(tenant_id, original_user_id);
CREATE INDEX IF NOT EXISTS idx_gov_archived_identities_merge ON gov_archived_identities(merge_operation_id);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE gov_correlation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_duplicate_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_merge_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_merge_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_archived_identities ENABLE ROW LEVEL SECURITY;

-- RLS policies for gov_correlation_rules
DROP POLICY IF EXISTS gov_correlation_rules_tenant_isolation ON gov_correlation_rules;
CREATE POLICY gov_correlation_rules_tenant_isolation ON gov_correlation_rules
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_duplicate_candidates
DROP POLICY IF EXISTS gov_duplicate_candidates_tenant_isolation ON gov_duplicate_candidates;
CREATE POLICY gov_duplicate_candidates_tenant_isolation ON gov_duplicate_candidates
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_merge_operations
DROP POLICY IF EXISTS gov_merge_operations_tenant_isolation ON gov_merge_operations;
CREATE POLICY gov_merge_operations_tenant_isolation ON gov_merge_operations
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_merge_audits
DROP POLICY IF EXISTS gov_merge_audits_tenant_isolation ON gov_merge_audits;
CREATE POLICY gov_merge_audits_tenant_isolation ON gov_merge_audits
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_archived_identities
DROP POLICY IF EXISTS gov_archived_identities_tenant_isolation ON gov_archived_identities;
CREATE POLICY gov_archived_identities_tenant_isolation ON gov_archived_identities
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Updated_at trigger for correlation rules
DROP TRIGGER IF EXISTS update_gov_correlation_rules_updated_at ON gov_correlation_rules;
CREATE TRIGGER update_gov_correlation_rules_updated_at
    BEFORE UPDATE ON gov_correlation_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE gov_correlation_rules IS 'Defines rules for detecting potential duplicate identities via attribute matching.';
COMMENT ON TABLE gov_duplicate_candidates IS 'Stores detected potential duplicate identity pairs with confidence scores.';
COMMENT ON TABLE gov_merge_operations IS 'Tracks in-progress and completed identity merge operations.';
COMMENT ON TABLE gov_merge_audits IS 'Immutable audit records capturing full state before and after each merge.';
COMMENT ON TABLE gov_archived_identities IS 'Soft-deleted identities preserved for audit and potential restoration.';

COMMENT ON COLUMN gov_correlation_rules.match_type IS 'Type of matching: exact, fuzzy, or phonetic.';
COMMENT ON COLUMN gov_correlation_rules.algorithm IS 'For fuzzy matching: levenshtein, jaro_winkler, or soundex.';
COMMENT ON COLUMN gov_correlation_rules.threshold IS 'Minimum similarity score (0.00-1.00) for fuzzy/phonetic matches.';
COMMENT ON COLUMN gov_correlation_rules.weight IS 'Weight factor for confidence score calculation.';
COMMENT ON COLUMN gov_correlation_rules.priority IS 'Processing order (higher = first).';

COMMENT ON COLUMN gov_duplicate_candidates.identity_a_id IS 'First identity in pair (canonical order: a < b).';
COMMENT ON COLUMN gov_duplicate_candidates.identity_b_id IS 'Second identity in pair (canonical order: a < b).';
COMMENT ON COLUMN gov_duplicate_candidates.confidence_score IS 'Overall match confidence (0.00-100.00).';
COMMENT ON COLUMN gov_duplicate_candidates.rule_matches IS 'JSONB array of individual rule match details.';

COMMENT ON COLUMN gov_merge_operations.source_identity_id IS 'Identity being archived (merged from).';
COMMENT ON COLUMN gov_merge_operations.target_identity_id IS 'Identity being kept (merged into).';
COMMENT ON COLUMN gov_merge_operations.entitlement_strategy IS 'How entitlements are consolidated: union, intersection, or manual.';
COMMENT ON COLUMN gov_merge_operations.attribute_selections IS 'JSONB mapping of attribute to selected source.';
COMMENT ON COLUMN gov_merge_operations.sod_override_reason IS 'If SoD violation was overridden, the justification.';

COMMENT ON COLUMN gov_merge_audits.source_snapshot IS 'Complete state of source identity at merge time.';
COMMENT ON COLUMN gov_merge_audits.target_snapshot IS 'Complete state of target identity before merge.';
COMMENT ON COLUMN gov_merge_audits.merged_snapshot IS 'Resulting state of target identity after merge.';
COMMENT ON COLUMN gov_merge_audits.attribute_decisions IS 'Record of each attribute selection decision.';
COMMENT ON COLUMN gov_merge_audits.entitlement_decisions IS 'Record of entitlement consolidation decisions.';
COMMENT ON COLUMN gov_merge_audits.sod_violations IS 'Any SoD violations detected/overridden during merge.';

COMMENT ON COLUMN gov_archived_identities.original_user_id IS 'Original user ID before archival.';
COMMENT ON COLUMN gov_archived_identities.snapshot IS 'Complete identity state at archival time.';
COMMENT ON COLUMN gov_archived_identities.external_references IS 'SCIM IDs, LDAP DNs, and other external references.';
