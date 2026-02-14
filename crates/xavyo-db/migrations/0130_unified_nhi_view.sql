-- Migration: F108 - Create unified NHI view
-- Purpose: Provides a single query point for all non-human identities

-- Create unified view for non-human identities
-- Note: RLS is inherited from underlying tables
CREATE OR REPLACE VIEW v_non_human_identities AS
SELECT
    sa.id,
    sa.tenant_id,
    sa.name,
    sa.purpose AS description,
    'service_account'::text AS nhi_type,
    sa.owner_id,
    sa.backup_owner_id,
    sa.status::text AS status,
    sa.created_at,
    sa.expires_at,
    sa.last_used_at AS last_activity_at,
    -- Use precomputed risk score from gov_nhi_risk_scores if available
    -- Otherwise calculate inline based on staleness and credential age
    COALESCE(
        rs.total_score,
        (
            CASE
                WHEN sa.last_used_at IS NULL THEN 40
                WHEN sa.last_used_at < NOW() - INTERVAL '90 days' THEN 40
                WHEN sa.last_used_at < NOW() - INTERVAL '30 days' THEN 20
                ELSE 0
            END
            +
            CASE
                WHEN sa.last_rotation_at IS NULL THEN 15
                WHEN sa.last_rotation_at < NOW() - INTERVAL '90 days' THEN 30
                WHEN sa.last_rotation_at < NOW() - INTERVAL '30 days' THEN 15
                ELSE 0
            END
        )
    )::integer AS risk_score,
    NULL::timestamptz AS next_certification_at,
    sa.last_certified_at
FROM gov_service_accounts sa
LEFT JOIN LATERAL (
    SELECT total_score FROM gov_nhi_risk_scores
    WHERE nhi_id = sa.id
    ORDER BY calculated_at DESC
    LIMIT 1
) rs ON true

UNION ALL

SELECT
    ag.id,
    ag.tenant_id,
    ag.name,
    ag.description,
    'ai_agent'::text AS nhi_type,
    ag.owner_id,
    ag.backup_owner_id,
    ag.status::text AS status,
    ag.created_at,
    ag.expires_at,
    ag.last_activity_at,
    -- Use computed risk_score if available, else map from risk_level enum
    COALESCE(
        ag.risk_score,
        CASE ag.risk_level::text
            WHEN 'critical' THEN 90
            WHEN 'high' THEN 70
            WHEN 'medium' THEN 40
            WHEN 'low' THEN 20
            ELSE 0
        END
    )::integer AS risk_score,
    ag.next_certification_at,
    ag.last_certified_at
FROM ai_agents ag;

-- Grant select permission to application role
-- Note: Adjust role name if different in your environment
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xavyo_app') THEN
        GRANT SELECT ON v_non_human_identities TO xavyo_app;
    END IF;
END $$;

-- Comment for documentation
COMMENT ON VIEW v_non_human_identities IS 'F108: Unified view of all non-human identities (service accounts + AI agents) for governance dashboard';
