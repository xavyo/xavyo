-- Persist advertised NHI access-request `nhi_type` so GET can return it.
-- BFF/UI advertise `nhi_type` on NhiAccessRequest (GET list/detail); POST
-- previously dropped it because the column did not exist.

ALTER TABLE gov_nhi_requests
    ADD COLUMN IF NOT EXISTS nhi_type TEXT
        CHECK (nhi_type IS NULL OR nhi_type IN ('service_account', 'agent', 'tool'));
