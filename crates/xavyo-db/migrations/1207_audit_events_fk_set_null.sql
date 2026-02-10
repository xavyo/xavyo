-- Fix FK constraint on gov_persona_audit_events to allow archetype/persona deletion.
-- Audit events are immutable records; setting the FK to NULL preserves the audit trail
-- while allowing the referenced archetype or persona to be deleted.

-- Drop existing FK constraints and recreate with ON DELETE SET NULL
ALTER TABLE gov_persona_audit_events
    DROP CONSTRAINT IF EXISTS gov_persona_audit_events_archetype_id_fkey;

ALTER TABLE gov_persona_audit_events
    ADD CONSTRAINT gov_persona_audit_events_archetype_id_fkey
    FOREIGN KEY (archetype_id) REFERENCES gov_persona_archetypes(id) ON DELETE SET NULL;

ALTER TABLE gov_persona_audit_events
    DROP CONSTRAINT IF EXISTS gov_persona_audit_events_persona_id_fkey;

ALTER TABLE gov_persona_audit_events
    ADD CONSTRAINT gov_persona_audit_events_persona_id_fkey
    FOREIGN KEY (persona_id) REFERENCES gov_personas(id) ON DELETE SET NULL;

-- Also relax the CHECK constraint since both can now be NULL after deletion
ALTER TABLE gov_persona_audit_events
    DROP CONSTRAINT IF EXISTS chk_audit_reference;

-- Update the immutability trigger to allow FK cascade SET NULL updates.
-- The original trigger unconditionally blocks all UPDATEs, which prevents
-- ON DELETE SET NULL from working. The new version allows updates that
-- only null out the FK columns (archetype_id, persona_id) while still
-- blocking all other modifications.
CREATE OR REPLACE FUNCTION prevent_persona_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Persona audit records cannot be deleted';
    END IF;
    -- Allow FK cascade SET NULL: only archetype_id/persona_id may change to NULL
    IF TG_OP = 'UPDATE' THEN
        IF (NEW.id IS DISTINCT FROM OLD.id)
            OR (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id)
            OR (NEW.event_type IS DISTINCT FROM OLD.event_type)
            OR (NEW.actor_id IS DISTINCT FROM OLD.actor_id)
            OR (NEW.event_data IS DISTINCT FROM OLD.event_data)
            OR (NEW.created_at IS DISTINCT FROM OLD.created_at)
            -- Allow archetype_id to be set to NULL (FK cascade)
            OR (NEW.archetype_id IS NOT NULL AND NEW.archetype_id IS DISTINCT FROM OLD.archetype_id)
            -- Allow persona_id to be set to NULL (FK cascade)
            OR (NEW.persona_id IS NOT NULL AND NEW.persona_id IS DISTINCT FROM OLD.persona_id)
        THEN
            RAISE EXCEPTION 'Persona audit records cannot be modified';
        END IF;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
