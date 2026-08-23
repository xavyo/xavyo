# Functional suite skips

Historical combined run recorded in `all-batches-results.md` (2026-02-10):
**1907 pass, 0 fail, 8 skip** (1940 total). This file documents those eight skips.
It is not a claim that the suite was re-run.

## Batch 8 — SCIM discovery (3)

From `batch-8-results.md`. The batch script treats HTTP 401 as “not implemented”
and skips.

| ID | Historical result | Reason |
|----|-------------------|--------|
| TC-SCIM-DEEP-006 | SKIP | `GET /scim/v2/ServiceProviderConfig` returned **401** (Feb 2026). |
| TC-SCIM-DEEP-007 | SKIP | `GET /scim/v2/Schemas` returned **401**. |
| TC-SCIM-DEEP-008 | SKIP | `GET /scim/v2/ResourceTypes` returned **401**. |

The shipped handlers (`service_provider_config`, `schemas`, `resource_types`) take
no auth. `scim_resource_router` mounts them on `discovery_routes` **without**
`ScimAuthLayer` (RFC 7643 §4). App mount in `apps/idp-api` does not wrap
`/scim/v2` in `jwt_auth_middleware`. Unit tests in `xavyo-api-scim` now call the
handlers and oneshot the resource router without `Authorization` to prove these
are not 401 from a JWT/SCIM auth layer.

## Batch 12 — sync / recon follow-ups (5)

From `batch-12-results.md`. Downstream GETs skip when the trigger never produced
an ID.

| ID | Historical result | Reason |
|----|-------------------|--------|
| TC-ST-014 | SKIP | No sync run ID. `TC-ST-012` trigger returned **409** (target not active). |
| TC-RE-004 | SKIP | No recon run ID. `TC-RE-001` trigger returned **409** (conflict / already running). |
| TC-RE-005 | SKIP | No recon run ID (same 409 on trigger). |
| TC-RE-006 | SKIP | No recon run ID (same 409 on trigger). |
| TC-RE-007 | SKIP | No recon run ID (same 409 on trigger). |
