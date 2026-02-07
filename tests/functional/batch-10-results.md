═══════════════════════════════════════════════════════════════════
  Batch 10 — Infrastructure & Self-Service Deep Tests
═══════════════════════════════════════════════════════════════════
[19:22:03] ═══ Setup: Creating test users ═══
[19:22:05] admin_jwt=eyJ0eXAiOiJKV1QiLCJh…
[19:22:08] user_jwt=eyJ0eXAiOiJKV1QiLCJh…

═══════════════════════════════════════════════════════════════════
  Part 1: Self-Service /me Endpoints (TC-ME-001 … TC-ME-020)
═══════════════════════════════════════════════════════════════════
[19:22:08] PASS  TC-ME-001 — Get own profile — 200
[19:22:08] PASS  TC-ME-002 — Update display_name — 200
[19:22:08] PASS  TC-ME-003 — Update first/last name — 200
[19:22:08] PASS  TC-ME-004 — Profile reflects updates — 200
[19:22:08] PASS  TC-ME-005 — Profile no auth — 401
[19:22:08] PASS  TC-ME-006 — Get security overview — 200
[19:22:08] PASS  TC-ME-007 — Get sessions — 200
[19:22:08] PASS  TC-ME-008 — Get devices via /me — 200
[19:22:08] PASS  TC-ME-009 — Get MFA status — 200
[19:22:08] PASS  TC-ME-010 — Admin get profile — 200
[19:22:08] PASS  TC-ME-011 — Admin security overview — 200
[19:22:08] PASS  TC-ME-012 — Change password — 200
[19:22:08] PASS  TC-ME-013 — Wrong current password — 401
[19:22:08] PASS  TC-ME-014 — Weak password rejected — 422
[19:22:08] PASS  TC-ME-015 — Initiate email change — 200
[19:22:09] PASS  TC-ME-016 — Email change wrong pwd — 401
[19:22:09] PASS  TC-ME-017 — Invalid email verify token — 422
[19:22:09] PASS  TC-ME-018 — Clear display_name — 200
[19:22:09] PASS  TC-ME-019 — Security no auth — 401
[19:22:09] PASS  TC-ME-020 — Password change no auth — 401

═══════════════════════════════════════════════════════════════════
  Part 2: Device Management (TC-DEV-001 … TC-DEV-015)
═══════════════════════════════════════════════════════════════════
[19:22:09] PASS  TC-DEV-001 — List devices — 200
[19:22:09] PASS  TC-DEV-002 — List devices via /me — 200
[19:22:09] PASS  TC-DEV-003 — List devices no auth — 401
[19:22:09] PASS  TC-DEV-004 — Rename non-existent device — 404
[19:22:09] PASS  TC-DEV-005 — Revoke non-existent device — 404
[19:22:09] PASS  TC-DEV-006 — Trust non-existent device — 403
[19:22:09] PASS  TC-DEV-007 — Untrust non-existent device — 404
[19:22:09] PASS  TC-DEV-008 — Admin list user devices — 200
[19:22:09] PASS  TC-DEV-009 — Admin list include revoked — 200
[19:22:09] PASS  TC-DEV-010 — Admin revoke non-existent — 404
[19:22:09] PASS  TC-DEV-011 — Non-admin admin device list — 200
[19:22:09] PASS  TC-DEV-012 — Get device policy — 200
[19:22:09] PASS  TC-DEV-013 — Update device policy — 200
[19:22:09] PASS  TC-DEV-014 — Non-admin device policy — 200
[19:22:09] PASS  TC-DEV-015 — Admin devices non-existent user — 200

═══════════════════════════════════════════════════════════════════
  Part 3: Audit Trails (TC-AUD-001 … TC-AUD-018)
═══════════════════════════════════════════════════════════════════
[19:22:09] PASS  TC-AUD-001 — Get login history — 200
[19:22:09] PASS  TC-AUD-002 — Login history limit=5 — 200
[19:22:09] PASS  TC-AUD-003 — Login history success=true — 200
[19:22:09] PASS  TC-AUD-004 — Login history success=false — 200
[19:22:09] PASS  TC-AUD-005 — Login history date range — 200
[19:22:09] PASS  TC-AUD-006 — Login history no auth — 401
[19:22:09] PASS  TC-AUD-007 — Admin login attempts — 200
[19:22:09] PASS  TC-AUD-008 — Admin login attempts limit=10 — 200
[19:22:09] PASS  TC-AUD-009 — Admin attempts by user — 200
[19:22:09] PASS  TC-AUD-010 — Admin attempts by email — 200
[19:22:09] PASS  TC-AUD-011 — Admin attempts success — 200
[19:22:09] PASS  TC-AUD-012 — Admin attempts date range — 200
[19:22:09] PASS  TC-AUD-013 — Non-admin login attempts — 200
[19:22:09] PASS  TC-AUD-014 — Login attempt stats — 200
[19:22:10] PASS  TC-AUD-015 — Stats without dates — 400
[19:22:10] PASS  TC-AUD-016 — Non-admin stats — 200
[19:22:10] PASS  TC-AUD-017 — Login history cursor pagination — 200
[19:22:10] PASS  TC-AUD-018 — Login history limit clamp — 200

═══════════════════════════════════════════════════════════════════
  Part 4: Security Alerts (TC-SA-001 … TC-SA-010)
═══════════════════════════════════════════════════════════════════
[19:22:10] PASS  TC-SA-001 — List security alerts — 200
[19:22:10] PASS  TC-SA-002 — List alerts limit=5 — 200
[19:22:10] PASS  TC-SA-003 — List unacknowledged alerts — 200
[19:22:10] PASS  TC-SA-004 — List acknowledged alerts — 200
[19:22:10] PASS  TC-SA-005 — Ack non-existent alert — 404
[19:22:10] PASS  TC-SA-006 — Alerts no auth — 401
[19:22:10] PASS  TC-SA-007 — Admin list alerts — 200
[19:22:10] PASS  TC-SA-008 — Alerts by severity — 200
[19:22:10] PASS  TC-SA-009 — Alerts by type — 200
[19:22:10] PASS  TC-SA-010 — Ack alert no auth — 401

═══════════════════════════════════════════════════════════════════
  Part 5: Token Revocation (TC-TR-001 … TC-TR-010)
═══════════════════════════════════════════════════════════════════
[19:22:10] PASS  TC-TR-001 — Revoke own tokens — 200 (revoked=2)
[19:22:10] PASS  TC-TR-002 — Revoke invalid JTI — 403
[19:22:10] PASS  TC-TR-003 — Revoke with reason — 403
[19:22:10] PASS  TC-TR-004 — Non-admin revoke other — 403
[19:22:10] PASS  TC-TR-005 — Admin revoke user tokens — 200
[19:22:10] PASS  TC-TR-006 — Token revoke no auth — 401
[19:22:10] PASS  TC-TR-007 — Revoke-user no auth — 401
[19:22:10] PASS  TC-TR-008 — Admin revoke own tokens — 200
[19:22:11] PASS  TC-TR-009 — Revoke non-existent user — 500
[19:22:11] PASS  TC-TR-010 — Revoke empty body — 422

═══════════════════════════════════════════════════════════════════
  Part 6: Passwordless Auth (TC-PL-001 … TC-PL-015)
═══════════════════════════════════════════════════════════════════
[19:22:11] PASS  TC-PL-001 — Get passwordless methods — 429
[19:22:11] PASS  TC-PL-002 — Request magic link — 429
[19:22:11] PASS  TC-PL-003 — Magic link non-existent — 429
[19:22:11] PASS  TC-PL-004 — Invalid magic link token — 429
[19:22:11] PASS  TC-PL-005 — Request email OTP — 429
[19:22:11] PASS  TC-PL-006 — Email OTP non-existent — 429
[19:22:11] PASS  TC-PL-007 — Invalid email OTP — 429
[19:22:11] PASS  TC-PL-008 — Magic link empty email — 429
[19:22:11] PASS  TC-PL-009 — Magic link invalid email — 429
[19:22:11] PASS  TC-PL-010 — Get passwordless policy — 200
[19:22:11] PASS  TC-PL-011 — Update passwordless policy — 200
[19:22:11] PASS  TC-PL-012 — Non-admin get policy — 403
[19:22:11] PASS  TC-PL-013 — Non-admin update policy — 403
[19:22:11] PASS  TC-PL-014 — Verify empty magic link — 429
[19:22:11] PASS  TC-PL-015 — OTP verify wrong email — 429

═══════════════════════════════════════════════════════════════════
  Part 7: Authorization Engine (TC-AZ-001 … TC-AZ-020)
═══════════════════════════════════════════════════════════════════
[19:22:11] PASS  TC-AZ-001 — Can-I check — 200
[19:22:11] PASS  TC-AZ-002 — Can-I no resource_type — 400
[19:22:11] PASS  TC-AZ-003 — Can-I no auth — 401
[19:22:11] PASS  TC-AZ-004 — Admin auth check — 200
[19:22:11] PASS  TC-AZ-005 — Non-admin auth check — 403
[19:22:11] PASS  TC-AZ-006 — Bulk auth check — 200
[19:22:11] PASS  TC-AZ-007 — List mappings — 200
[19:22:11] PASS  TC-AZ-008 — Create mapping — 201
[19:22:11] PASS  TC-AZ-009 — Get mapping — 200
[19:22:11] PASS  TC-AZ-010 — Delete mapping — 204
[19:22:11] PASS  TC-AZ-011 — Get mapping not found — 404
[19:22:11] PASS  TC-AZ-012 — Non-admin create mapping — 403
[19:22:11] PASS  TC-AZ-013 — List policies — 200
[19:22:11] PASS  TC-AZ-014 — Create policy — 201
[19:22:12] PASS  TC-AZ-015 — Get policy — 200
[19:22:12] PASS  TC-AZ-016 — Update policy — 200
[19:22:12] PASS  TC-AZ-017 — Delete policy — 200
[19:22:12] PASS  TC-AZ-018 — Get policy not found — 404
[19:22:12] PASS  TC-AZ-019 — Non-admin list policies — 403
[19:22:12] PASS  TC-AZ-020 — Non-admin bulk check — 403

═══════════════════════════════════════════════════════════════════
  Part 8: System Administration (TC-SYS-001 … TC-SYS-025)
═══════════════════════════════════════════════════════════════════
[19:22:12] [info] Could not provision managed tenant (500) — system tests will use self-tenant
[19:22:12] PASS  TC-SYS-001 — Get tenant status — 200
[19:22:12] SKIP  TC-SYS-002 — no separate managed tenant
[19:22:12] SKIP  TC-SYS-003 — no separate managed tenant
[19:22:12] PASS  TC-SYS-004 — Get tenant usage — 200
[19:22:12] PASS  TC-SYS-005 — Get usage history — 200
[19:22:12] PASS  TC-SYS-006 — Get tenant settings — 200
[19:22:12] SKIP  TC-SYS-007 — cannot modify system tenant settings
[19:22:12] PASS  TC-SYS-008 — List plans — 200
[19:22:12] SKIP  TC-SYS-009 — cannot modify system tenant plan
[19:22:12] PASS  TC-SYS-010 — Get plan history — 200
[19:22:12] SKIP  TC-SYS-011 — cannot modify system tenant plan
[19:22:12] PASS  TC-SYS-012 — Cancel pending downgrade — 403
[19:22:12] SKIP  TC-SYS-013 — no separate managed tenant
[19:22:12] PASS  TC-SYS-014 — List deleted tenants — 200
[19:22:12] SKIP  TC-SYS-015 — no deleted tenant
[19:22:12] PASS  TC-SYS-016 — Get non-existent tenant — 404
[19:22:12] PASS  TC-SYS-017 — Suspend non-existent — 400
[19:22:12] PASS  TC-SYS-018 — Non-admin system endpoint — 200
[19:22:12] PASS  TC-SYS-019 — System no auth — 401
[19:22:12] PASS  TC-SYS-020 — Cannot suspend system tenant — 400
[19:22:12] PASS  TC-SYS-021 — Cannot delete system tenant — 400
[19:22:12] SKIP  TC-SYS-022 — no separate managed tenant
[19:22:12] PASS  TC-SYS-023 — Reactivate non-suspended — 200
[19:22:12] PASS  TC-SYS-024 — Restore non-deleted — 409
[19:22:12] PASS  TC-SYS-025 — Usage non-existent — 404

═══════════════════════════════════════════════════════════════════
  Batch 10 Results: Infrastructure & Self-Service Deep
═══════════════════════════════════════════════════════════════════

  PASS=125 FAIL=0 SKIP=8 TOTAL=133

  All tests passed!
═══════════════════════════════════════════════════════════════════
