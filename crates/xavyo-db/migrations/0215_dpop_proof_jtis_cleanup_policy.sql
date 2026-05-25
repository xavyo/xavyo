-- Migration: make the DPoP replay-cache vacuum actually work under FORCE RLS.
--
-- dpop_proof_jtis is FORCE ROW LEVEL SECURITY with a tenant-isolation policy
-- (USING tenant_id = current_setting('app.current_tenant', true)). The periodic
-- vacuum (DpopProofJti::cleanup_expired) runs with NO tenant context, so under
-- that policy `tenant_id = NULL` matches nothing and the DELETE prunes nothing —
-- the replay cache grows unbounded.
--
-- Fix: add a second (permissive) DELETE policy that allows removing rows whose
-- proof-acceptance window has already lapsed, regardless of tenant. This is
-- safe: an EXPIRED jti carries no replay-protection value (a proof whose `iat`
-- is past the acceptance window is independently rejected by the freshness
-- check), so pruning expired rows — even cross-tenant — has no security effect.
-- RLS policies are permissive (OR-combined), so tenant isolation for live rows
-- is unchanged; only already-expired rows become deletable by the vacuum.

DROP POLICY IF EXISTS expired_cleanup_policy ON dpop_proof_jtis;
CREATE POLICY expired_cleanup_policy ON dpop_proof_jtis
    FOR DELETE
    USING (expires_at < now());

COMMENT ON POLICY expired_cleanup_policy ON dpop_proof_jtis IS
    'Permits the tenant-less periodic vacuum to delete already-expired replay-cache rows (expired jtis carry no replay-protection value); tenant isolation for live rows is unchanged';
