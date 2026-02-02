-- Migration: 063_001_persona_management
-- Feature: F063 - Persona Management
-- Description: Virtual alternative identities for users (IGA persona concept)

-- ============================================================================
-- ENUM TYPES
-- ============================================================================

-- Persona lifecycle status
DO $$ BEGIN
    CREATE TYPE persona_status AS ENUM (
        'draft',      -- Created but not yet active
        'active',     -- Fully operational
        'expiring',   -- Within notification window of expiration
        'expired',    -- Past valid_until, auto-deactivated
        'suspended',  -- Manually suspended
        'archived'    -- Soft-deleted, preserved for audit
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Persona link type (relationship between physical user and persona)
DO $$ BEGIN
    CREATE TYPE persona_link_type AS ENUM (
        'owner',      -- Primary ownership link
        'delegate'    -- Delegated access (future use)
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Persona audit event types
DO $$ BEGIN
    CREATE TYPE persona_audit_event_type AS ENUM (
        'archetype_created',
        'archetype_updated',
        'archetype_deleted',
        'persona_created',
        'persona_activated',
        'persona_deactivated',
        'persona_expired',
        'persona_extended',
        'persona_archived',
        'context_switched',
        'context_switched_back',
        'attributes_propagated',
        'entitlement_added',
        'entitlement_removed'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================================================================
-- TABLES
-- ============================================================================

-- PersonaArchetype: Defines templates for persona types with attribute mappings and lifecycle policies
CREATE TABLE IF NOT EXISTS gov_persona_archetypes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    naming_pattern VARCHAR(255) NOT NULL,
    attribute_mappings JSONB NOT NULL DEFAULT '{}',
    default_entitlements JSONB,
    lifecycle_policy JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name per tenant
    CONSTRAINT uq_persona_archetype_name UNIQUE (tenant_id, name),
    -- Validate naming_pattern contains placeholder
    CONSTRAINT chk_naming_pattern_valid CHECK (
        naming_pattern ~ '\{[a-z_]+\}'
    )
);

-- Persona: Virtual identity linked to a physical user, created from an archetype
CREATE TABLE IF NOT EXISTS gov_personas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    archetype_id UUID NOT NULL REFERENCES gov_persona_archetypes(id),
    physical_user_id UUID NOT NULL,
    persona_name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}',
    status persona_status NOT NULL DEFAULT 'draft',
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated_at TIMESTAMPTZ,
    deactivated_by UUID,
    deactivation_reason TEXT,

    -- One persona per archetype per user (IGA constraint)
    CONSTRAINT uq_persona_user_archetype UNIQUE (tenant_id, physical_user_id, archetype_id),
    -- Unique persona name per tenant
    CONSTRAINT uq_persona_name UNIQUE (tenant_id, persona_name),
    -- valid_until must be after valid_from
    CONSTRAINT chk_valid_period CHECK (
        valid_until IS NULL OR valid_until > valid_from
    ),
    -- Deactivation consistency
    CONSTRAINT chk_deactivation_consistency CHECK (
        (status NOT IN ('suspended', 'archived')) OR
        (deactivated_at IS NOT NULL AND deactivated_by IS NOT NULL)
    )
);

-- PersonaLink: Explicit link between physical user and persona (persona reference)
CREATE TABLE IF NOT EXISTS gov_persona_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    physical_user_id UUID NOT NULL,
    persona_id UUID NOT NULL REFERENCES gov_personas(id) ON DELETE CASCADE,
    link_type persona_link_type NOT NULL DEFAULT 'owner',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,

    -- Prevent duplicate links
    CONSTRAINT uq_persona_link UNIQUE (tenant_id, physical_user_id, persona_id)
);

-- PersonaSession: Tracks which persona is currently active for a user session
CREATE TABLE IF NOT EXISTS gov_persona_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    active_persona_id UUID REFERENCES gov_personas(id),
    previous_persona_id UUID REFERENCES gov_personas(id),
    switch_reason TEXT,
    switched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Expiration must be after creation
    CONSTRAINT chk_session_expiration CHECK (expires_at > created_at)
);

-- PersonaAuditEvent: Audit trail for all persona-related actions (immutable)
CREATE TABLE IF NOT EXISTS gov_persona_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    persona_id UUID REFERENCES gov_personas(id),
    archetype_id UUID REFERENCES gov_persona_archetypes(id),
    event_type persona_audit_event_type NOT NULL,
    actor_id UUID NOT NULL,
    event_data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- At least one of persona_id or archetype_id must be set
    CONSTRAINT chk_audit_reference CHECK (
        persona_id IS NOT NULL OR archetype_id IS NOT NULL
    )
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- PersonaArchetype indexes
CREATE INDEX IF NOT EXISTS idx_persona_archetypes_tenant ON gov_persona_archetypes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_persona_archetypes_active ON gov_persona_archetypes(tenant_id)
    WHERE is_active = true;

-- Persona indexes
CREATE INDEX IF NOT EXISTS idx_personas_tenant ON gov_personas(tenant_id);
CREATE INDEX IF NOT EXISTS idx_personas_physical_user ON gov_personas(tenant_id, physical_user_id);
CREATE INDEX IF NOT EXISTS idx_personas_archetype ON gov_personas(tenant_id, archetype_id);
CREATE INDEX IF NOT EXISTS idx_personas_status ON gov_personas(tenant_id, status)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_personas_expiring ON gov_personas(tenant_id, valid_until)
    WHERE status = 'active' AND valid_until IS NOT NULL;

-- PersonaLink indexes
CREATE INDEX IF NOT EXISTS idx_persona_links_tenant ON gov_persona_links(tenant_id);
CREATE INDEX IF NOT EXISTS idx_persona_links_user ON gov_persona_links(tenant_id, physical_user_id);
CREATE INDEX IF NOT EXISTS idx_persona_links_persona ON gov_persona_links(tenant_id, persona_id);

-- PersonaSession indexes
CREATE INDEX IF NOT EXISTS idx_persona_sessions_tenant ON gov_persona_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_persona_sessions_user ON gov_persona_sessions(tenant_id, user_id);
-- Note: Cannot use NOW() in partial index predicate (not immutable)
-- Use expires_at for filtering at query time
CREATE INDEX IF NOT EXISTS idx_persona_sessions_active ON gov_persona_sessions(tenant_id, user_id, active_persona_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_persona_sessions_expires ON gov_persona_sessions(tenant_id, expires_at);

-- PersonaAuditEvent indexes
CREATE INDEX IF NOT EXISTS idx_persona_audit_tenant ON gov_persona_audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_persona_audit_persona ON gov_persona_audit_events(tenant_id, persona_id);
CREATE INDEX IF NOT EXISTS idx_persona_audit_archetype ON gov_persona_audit_events(tenant_id, archetype_id);
CREATE INDEX IF NOT EXISTS idx_persona_audit_actor ON gov_persona_audit_events(tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS idx_persona_audit_type ON gov_persona_audit_events(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_persona_audit_created ON gov_persona_audit_events(tenant_id, created_at DESC);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE gov_persona_archetypes ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_personas ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_persona_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_persona_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gov_persona_audit_events ENABLE ROW LEVEL SECURITY;

-- RLS policies for gov_persona_archetypes
DROP POLICY IF EXISTS gov_persona_archetypes_tenant_isolation ON gov_persona_archetypes;
CREATE POLICY gov_persona_archetypes_tenant_isolation ON gov_persona_archetypes
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_personas
DROP POLICY IF EXISTS gov_personas_tenant_isolation ON gov_personas;
CREATE POLICY gov_personas_tenant_isolation ON gov_personas
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_persona_links
DROP POLICY IF EXISTS gov_persona_links_tenant_isolation ON gov_persona_links;
CREATE POLICY gov_persona_links_tenant_isolation ON gov_persona_links
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_persona_sessions
DROP POLICY IF EXISTS gov_persona_sessions_tenant_isolation ON gov_persona_sessions;
CREATE POLICY gov_persona_sessions_tenant_isolation ON gov_persona_sessions
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- RLS policies for gov_persona_audit_events
DROP POLICY IF EXISTS gov_persona_audit_events_tenant_isolation ON gov_persona_audit_events;
CREATE POLICY gov_persona_audit_events_tenant_isolation ON gov_persona_audit_events
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Ensure update_updated_at_column function exists
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Updated_at trigger for archetypes
DROP TRIGGER IF EXISTS update_persona_archetypes_updated_at ON gov_persona_archetypes;
CREATE TRIGGER update_persona_archetypes_updated_at
    BEFORE UPDATE ON gov_persona_archetypes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Updated_at trigger for personas
DROP TRIGGER IF EXISTS update_personas_updated_at ON gov_personas;
CREATE TRIGGER update_personas_updated_at
    BEFORE UPDATE ON gov_personas
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Prevent modification of audit records
CREATE OR REPLACE FUNCTION prevent_persona_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Persona audit records cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevent_persona_audit_update ON gov_persona_audit_events;
CREATE TRIGGER prevent_persona_audit_update
    BEFORE UPDATE ON gov_persona_audit_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_persona_audit_modification();

DROP TRIGGER IF EXISTS prevent_persona_audit_delete ON gov_persona_audit_events;
CREATE TRIGGER prevent_persona_audit_delete
    BEFORE DELETE ON gov_persona_audit_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_persona_audit_modification();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE gov_persona_archetypes IS 'Defines templates for persona types with attribute mappings and lifecycle policies (IGA archetype concept).';
COMMENT ON TABLE gov_personas IS 'Virtual identities linked to physical users - alternative representations of physical persons.';
COMMENT ON TABLE gov_persona_links IS 'Explicit links between physical users and their personas (persona reference).';
COMMENT ON TABLE gov_persona_sessions IS 'Tracks active persona context for user sessions with JWT enhancement.';
COMMENT ON TABLE gov_persona_audit_events IS 'Immutable audit trail for all persona-related actions.';

COMMENT ON COLUMN gov_persona_archetypes.naming_pattern IS 'Template for generating persona names (e.g., "admin.{username}"). Must contain at least one placeholder.';
COMMENT ON COLUMN gov_persona_archetypes.attribute_mappings IS 'JSONB defining how attributes propagate: {propagate:[], computed:[], persona_only:[]}.';
COMMENT ON COLUMN gov_persona_archetypes.default_entitlements IS 'JSONB of entitlements auto-assigned to new personas of this archetype.';
COMMENT ON COLUMN gov_persona_archetypes.lifecycle_policy IS 'JSONB with validity days, notification settings, extension rules, deactivation behavior.';

COMMENT ON COLUMN gov_personas.physical_user_id IS 'Reference to the owning physical user in the users table.';
COMMENT ON COLUMN gov_personas.persona_name IS 'Generated name from archetype naming_pattern (e.g., "admin.john.doe").';
COMMENT ON COLUMN gov_personas.attributes IS 'JSONB storing overrides, persona_specific, inherited, and last_propagation_at.';
COMMENT ON COLUMN gov_personas.status IS 'Lifecycle status: draft, active, expiring, expired, suspended, archived.';
COMMENT ON COLUMN gov_personas.valid_from IS 'When persona becomes valid for use.';
COMMENT ON COLUMN gov_personas.valid_until IS 'Optional expiration time for time-limited personas.';

COMMENT ON COLUMN gov_persona_links.link_type IS 'Type of relationship: owner (primary) or delegate (future delegated access).';

COMMENT ON COLUMN gov_persona_sessions.user_id IS 'Physical user who owns this session.';
COMMENT ON COLUMN gov_persona_sessions.active_persona_id IS 'Currently active persona (NULL = operating as physical user).';
COMMENT ON COLUMN gov_persona_sessions.previous_persona_id IS 'Previous persona before last switch (for audit trail).';
COMMENT ON COLUMN gov_persona_sessions.switch_reason IS 'User-provided reason for the context switch.';

COMMENT ON COLUMN gov_persona_audit_events.persona_id IS 'Related persona (NULL for archetype-only events).';
COMMENT ON COLUMN gov_persona_audit_events.archetype_id IS 'Related archetype (NULL for persona-only events).';
COMMENT ON COLUMN gov_persona_audit_events.actor_id IS 'User who performed the action.';
COMMENT ON COLUMN gov_persona_audit_events.event_data IS 'JSONB with event-specific details (before/after state, changed attributes, etc.).';
