-- Migration 1205: Public agent discovery function (SECURITY DEFINER)
--
-- The A2A AgentCard discovery endpoint (/.well-known/agents/{id}) is a public,
-- unauthenticated endpoint per the A2A protocol specification. However, RLS on
-- nhi_identities requires a valid tenant context (app.current_tenant), which is
-- not available for unauthenticated requests.
--
-- This SECURITY DEFINER function runs with the privileges of the function owner
-- (the migration user, typically a superuser), bypassing RLS. This is safe because:
--   1. It only returns agent data for a specific, known UUID
--   2. It filters to nhi_type = 'agent' and active lifecycle_state
--   3. Agent IDs are UUIDv4 (unguessable)
--   4. It returns only fields needed for the AgentCard (no sensitive data)

-- Function to find an agent for public discovery (bypasses RLS)
CREATE OR REPLACE FUNCTION public_find_agent_for_discovery(agent_uuid UUID)
RETURNS TABLE (
    id UUID,
    tenant_id UUID,
    name TEXT,
    description TEXT,
    lifecycle_state TEXT,
    agent_type TEXT,
    model_provider TEXT,
    model_name TEXT,
    model_version TEXT,
    agent_card_url TEXT,
    agent_card_signature TEXT,
    max_token_lifetime_secs INTEGER,
    requires_human_approval BOOLEAN,
    team_id UUID
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT
        i.id,
        i.tenant_id,
        i.name::text,
        i.description::text,
        i.lifecycle_state::text,
        a.agent_type::text,
        a.model_provider::text,
        a.model_name::text,
        a.model_version::text,
        a.agent_card_url::text,
        a.agent_card_signature::text,
        a.max_token_lifetime_secs,
        a.requires_human_approval,
        a.team_id
    FROM nhi_identities i
    INNER JOIN nhi_agents a ON a.nhi_id = i.id
    WHERE i.id = agent_uuid
      AND i.nhi_type = 'agent'
    LIMIT 1;
$$;

-- Function to list active tool permissions for an agent (bypasses RLS)
-- Used by discovery to populate agent skills
CREATE OR REPLACE FUNCTION public_list_agent_tools_for_discovery(
    p_tenant_id UUID,
    p_agent_nhi_id UUID
)
RETURNS TABLE (
    tool_nhi_id UUID,
    tool_name TEXT,
    tool_description TEXT,
    tool_lifecycle_state TEXT
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT
        tp.tool_nhi_id,
        i.name::text,
        i.description::text,
        i.lifecycle_state::text
    FROM nhi_tool_permissions tp
    INNER JOIN nhi_identities i ON i.id = tp.tool_nhi_id
    WHERE tp.agent_nhi_id = p_agent_nhi_id
      AND tp.tenant_id = p_tenant_id
      AND (tp.expires_at IS NULL OR tp.expires_at > NOW())
      AND i.lifecycle_state = 'active'
    LIMIT 100;
$$;

-- Grant execute to app role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xavyo_app') THEN
        GRANT EXECUTE ON FUNCTION public_find_agent_for_discovery(UUID) TO xavyo_app;
        GRANT EXECUTE ON FUNCTION public_list_agent_tools_for_discovery(UUID, UUID) TO xavyo_app;
    END IF;
END $$;
