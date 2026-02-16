-- Fix gov_nhi_risk_scores.risk_level column type.
--
-- Migration 0057 used gov_risk_level (from 0032_governance_entitlements) but
-- the Rust GovNhiRiskScore model derives sqlx::Type with type_name = "risk_level"
-- (from 0038_identity_risk_scoring). Both enums have identical variants
-- (low, medium, high, critical) so the cast is lossless.
--
-- Without this fix, any SELECT on gov_nhi_risk_scores that returns a row
-- fails with a sqlx type mismatch (OID for gov_risk_level != risk_level),
-- causing ext-authz to return HTTP 500 for agents with risk scores.

ALTER TABLE gov_nhi_risk_scores
    ALTER COLUMN risk_level TYPE risk_level
    USING risk_level::text::risk_level;
