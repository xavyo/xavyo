-- Persist advertised NHI certification campaign scope.
-- POST /governance/nhis/certification/campaigns accepted `scope` from the BFF
-- (`all` | `by_type` | `specific`) but dropped it; launch then applied leftover
-- type/id filters regardless of the advertised scope.

ALTER TABLE gov_nhi_certification_campaigns
    ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'all'
        CHECK (scope IN ('all', 'by_type', 'specific'));

UPDATE gov_nhi_certification_campaigns
SET scope = CASE
    WHEN specific_nhi_ids IS NOT NULL AND cardinality(specific_nhi_ids) > 0 THEN 'specific'
    WHEN nhi_type_filter IS NOT NULL THEN 'by_type'
    ELSE 'all'
END
WHERE scope = 'all';
