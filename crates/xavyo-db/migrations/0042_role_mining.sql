-- Role Mining and Analytics (F041)
-- Analyze access patterns to discover and optimize roles

-- Job status enum
DO $$ BEGIN
    CREATE TYPE mining_job_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Candidate promotion status enum
DO $$ BEGIN
    CREATE TYPE candidate_promotion_status AS ENUM ('pending', 'promoted', 'dismissed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Excessive privilege status enum
DO $$ BEGIN
    CREATE TYPE privilege_flag_status AS ENUM ('pending', 'reviewed', 'remediated', 'accepted');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Consolidation suggestion status enum
DO $$ BEGIN
    CREATE TYPE consolidation_status AS ENUM ('pending', 'merged', 'dismissed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Simulation status enum
DO $$ BEGIN
    CREATE TYPE simulation_status AS ENUM ('draft', 'executed', 'applied', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Scenario type enum
DO $$ BEGIN
    CREATE TYPE scenario_type AS ENUM ('add_entitlement', 'remove_entitlement', 'add_role', 'remove_role', 'modify_role');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Trend direction enum
DO $$ BEGIN
    CREATE TYPE trend_direction AS ENUM ('up', 'stable', 'down');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Role Mining Jobs table
CREATE TABLE IF NOT EXISTS gov_role_mining_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    status mining_job_status NOT NULL DEFAULT 'pending',
    parameters JSONB NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    progress_percent INT NOT NULL DEFAULT 0 CHECK (progress_percent >= 0 AND progress_percent <= 100),
    candidate_count INT NOT NULL DEFAULT 0,
    excessive_privilege_count INT NOT NULL DEFAULT 0,
    consolidation_suggestion_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Role Candidates table
CREATE TABLE IF NOT EXISTS gov_role_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES gov_role_mining_jobs(id) ON DELETE CASCADE,
    proposed_name VARCHAR(255) NOT NULL,
    confidence_score DECIMAL(5,4) NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 1),
    member_count INT NOT NULL,
    entitlement_ids UUID[] NOT NULL DEFAULT '{}',
    user_ids UUID[] NOT NULL DEFAULT '{}',
    promotion_status candidate_promotion_status NOT NULL DEFAULT 'pending',
    promoted_role_id UUID,
    dismissed_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Access Patterns table
CREATE TABLE IF NOT EXISTS gov_access_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES gov_role_mining_jobs(id) ON DELETE CASCADE,
    entitlement_ids UUID[] NOT NULL DEFAULT '{}',
    frequency INT NOT NULL,
    user_count INT NOT NULL,
    sample_user_ids UUID[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Excessive Privilege Flags table
CREATE TABLE IF NOT EXISTS gov_excessive_privileges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES gov_role_mining_jobs(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    peer_group_id UUID,
    deviation_percent DECIMAL(5,2) NOT NULL,
    excess_entitlements UUID[] NOT NULL DEFAULT '{}',
    peer_average DECIMAL(10,2) NOT NULL,
    user_count INT NOT NULL,
    status privilege_flag_status NOT NULL DEFAULT 'pending',
    reviewed_at TIMESTAMPTZ,
    reviewed_by UUID REFERENCES users(id),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Consolidation Suggestions table
CREATE TABLE IF NOT EXISTS gov_consolidation_suggestions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES gov_role_mining_jobs(id) ON DELETE CASCADE,
    role_a_id UUID NOT NULL,
    role_b_id UUID NOT NULL,
    overlap_percent DECIMAL(5,2) NOT NULL CHECK (overlap_percent >= 0 AND overlap_percent <= 100),
    shared_entitlements UUID[] NOT NULL DEFAULT '{}',
    unique_to_a UUID[] NOT NULL DEFAULT '{}',
    unique_to_b UUID[] NOT NULL DEFAULT '{}',
    status consolidation_status NOT NULL DEFAULT 'pending',
    dismissed_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Role Simulations table
CREATE TABLE IF NOT EXISTS gov_role_simulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    scenario_type scenario_type NOT NULL,
    target_role_id UUID,
    changes JSONB NOT NULL DEFAULT '{}',
    affected_users UUID[] NOT NULL DEFAULT '{}',
    access_gained JSONB NOT NULL DEFAULT '{}',
    access_lost JSONB NOT NULL DEFAULT '{}',
    status simulation_status NOT NULL DEFAULT 'draft',
    applied_at TIMESTAMPTZ,
    applied_by UUID REFERENCES users(id),
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Role Metrics table
CREATE TABLE IF NOT EXISTS gov_role_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    utilization_rate DECIMAL(5,4) NOT NULL CHECK (utilization_rate >= 0 AND utilization_rate <= 1),
    coverage_rate DECIMAL(5,4) NOT NULL CHECK (coverage_rate >= 0 AND coverage_rate <= 1),
    user_count INT NOT NULL DEFAULT 0,
    active_user_count INT NOT NULL DEFAULT 0,
    entitlement_usage JSONB NOT NULL DEFAULT '[]',
    trend_direction trend_direction NOT NULL DEFAULT 'stable',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for gov_role_mining_jobs
CREATE INDEX IF NOT EXISTS idx_gov_role_mining_jobs_tenant_status
    ON gov_role_mining_jobs(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_role_mining_jobs_created_by
    ON gov_role_mining_jobs(created_by);
CREATE INDEX IF NOT EXISTS idx_gov_role_mining_jobs_created_at
    ON gov_role_mining_jobs(tenant_id, created_at DESC);

-- Indexes for gov_role_candidates
CREATE INDEX IF NOT EXISTS idx_gov_role_candidates_job
    ON gov_role_candidates(tenant_id, job_id);
CREATE INDEX IF NOT EXISTS idx_gov_role_candidates_status
    ON gov_role_candidates(tenant_id, promotion_status);
CREATE INDEX IF NOT EXISTS idx_gov_role_candidates_confidence
    ON gov_role_candidates(tenant_id, job_id, confidence_score DESC);

-- Indexes for gov_access_patterns
CREATE INDEX IF NOT EXISTS idx_gov_access_patterns_job
    ON gov_access_patterns(tenant_id, job_id);

-- Indexes for gov_excessive_privileges
CREATE INDEX IF NOT EXISTS idx_gov_excessive_privileges_job
    ON gov_excessive_privileges(tenant_id, job_id);
CREATE INDEX IF NOT EXISTS idx_gov_excessive_privileges_user
    ON gov_excessive_privileges(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_gov_excessive_privileges_status
    ON gov_excessive_privileges(tenant_id, status);

-- Indexes for gov_consolidation_suggestions
CREATE INDEX IF NOT EXISTS idx_gov_consolidation_suggestions_job
    ON gov_consolidation_suggestions(tenant_id, job_id);
CREATE INDEX IF NOT EXISTS idx_gov_consolidation_suggestions_roles
    ON gov_consolidation_suggestions(tenant_id, role_a_id, role_b_id);

-- Indexes for gov_role_simulations
CREATE INDEX IF NOT EXISTS idx_gov_role_simulations_tenant
    ON gov_role_simulations(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gov_role_simulations_created_at
    ON gov_role_simulations(tenant_id, created_at DESC);

-- Indexes for gov_role_metrics
CREATE INDEX IF NOT EXISTS idx_gov_role_metrics_role
    ON gov_role_metrics(tenant_id, role_id);
CREATE INDEX IF NOT EXISTS idx_gov_role_metrics_calculated
    ON gov_role_metrics(tenant_id, calculated_at DESC);

-- Row-Level Security
ALTER TABLE gov_role_mining_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_role_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_access_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_excessive_privileges ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_consolidation_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_role_simulations ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_role_metrics ENABLE ROW LEVEL SECURITY;

-- RLS Policies for gov_role_mining_jobs
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_mining_jobs;
CREATE POLICY tenant_isolation_policy ON gov_role_mining_jobs
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = ''
            THEN true
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- RLS Policies for gov_role_candidates
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_candidates;
CREATE POLICY tenant_isolation_policy ON gov_role_candidates
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = ''
            THEN true
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- RLS Policies for gov_access_patterns
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_access_patterns;
CREATE POLICY tenant_isolation_policy ON gov_access_patterns
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = ''
            THEN true
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- RLS Policies for gov_excessive_privileges
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_excessive_privileges;
CREATE POLICY tenant_isolation_policy ON gov_excessive_privileges
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = ''
            THEN true
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- RLS Policies for gov_consolidation_suggestions
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_consolidation_suggestions;
CREATE POLICY tenant_isolation_policy ON gov_consolidation_suggestions
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = ''
            THEN true
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- RLS Policies for gov_role_simulations
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_simulations;
CREATE POLICY tenant_isolation_policy ON gov_role_simulations
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = ''
            THEN true
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- RLS Policies for gov_role_metrics
DROP POLICY IF EXISTS tenant_isolation_policy ON gov_role_metrics;
CREATE POLICY tenant_isolation_policy ON gov_role_metrics
    USING (
        CASE
            WHEN current_setting('app.current_tenant', true) IS NULL OR current_setting('app.current_tenant', true) = ''
            THEN true
            ELSE tenant_id = current_setting('app.current_tenant')::uuid
        END
    );

-- Updated_at triggers
CREATE OR REPLACE FUNCTION update_gov_role_mining_jobs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_gov_role_mining_jobs_updated_at ON gov_role_mining_jobs;
CREATE TRIGGER trigger_update_gov_role_mining_jobs_updated_at
    BEFORE UPDATE ON gov_role_mining_jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_gov_role_mining_jobs_updated_at();
