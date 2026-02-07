═══════════════════════════════════════════════════════════════════
  Batch 11 — Admin Features & Governance Deep Tests
═══════════════════════════════════════════════════════════════════
[20:02:29] ═══ Setup: Creating test users ═══
[20:02:33] admin_jwt=eyJ0eXAiOiJKV1QiLCJh…
[20:02:36] user_jwt=eyJ0eXAiOiJKV1QiLCJh…

═══════════════════════════════════════════════════════════════════
  Part 1: IP Restrictions (TC-IP-001 … TC-IP-015)
═══════════════════════════════════════════════════════════════════
[20:02:36] PASS  TC-IP-001 — Get IP settings — 200
[20:02:36] PASS  TC-IP-002 — Update IP settings — 200
[20:02:36] PASS  TC-IP-003 — List IP rules — 200
[20:02:36] PASS  TC-IP-004 — Create whitelist rule — 201
[20:02:36] PASS  TC-IP-005 — Get IP rule — 200
[20:02:36] PASS  TC-IP-006 — Update IP rule — 200
[20:02:37] PASS  TC-IP-007 — Create blacklist rule — 201
[20:02:37] PASS  TC-IP-008 — Validate IP — 200
[20:02:37] PASS  TC-IP-009 — Validate IP with role — 200
[20:02:37] PASS  TC-IP-010 — Invalid CIDR rejected — 400
[20:02:37] PASS  TC-IP-011 — Non-admin IP settings — 200
[20:02:37] PASS  TC-IP-012 — No auth IP rules — 401
[20:02:37] PASS  TC-IP-013 — Delete IP rule — 204
[20:02:37] PASS  TC-IP-014 — Get deleted rule — 404
[20:02:37] PASS  TC-IP-015 — Set whitelist mode — 200

═══════════════════════════════════════════════════════════════════
  Part 2: Branding & Email Templates (TC-BR-001 … TC-BR-018)
═══════════════════════════════════════════════════════════════════
[20:02:37] PASS  TC-BR-001 — Get branding — 200
[20:02:37] PASS  TC-BR-002 — Update branding — 200
[20:02:37] PASS  TC-BR-003 — Branding reflects update — 200
[20:02:37] PASS  TC-BR-004 — Update branding URLs — 200
[20:02:37] PASS  TC-BR-005 — List assets — 200
[20:02:37] PASS  TC-BR-006 — List email templates — 200
[20:02:37] PASS  TC-BR-007 — Get welcome template — 200
[20:02:37] PASS  TC-BR-008 — Get email_verification template — 200
[20:02:37] PASS  TC-BR-009 — Update email template — 200
[20:02:37] PASS  TC-BR-010 — Preview email template — 200
[20:02:37] PASS  TC-BR-011 — Reset email template — 200
[20:02:37] PASS  TC-BR-012 — Non-existent template — 422
[20:02:37] PASS  TC-BR-013 — Non-admin branding — 403
[20:02:38] PASS  TC-BR-014 — Non-admin update branding — 403
[20:02:38] PASS  TC-BR-015 — No auth branding — 401
[20:02:38] PASS  TC-BR-016 — Asset not found — 404
[20:02:38] PASS  TC-BR-017 — Delete asset not found — 404
[20:02:38] PASS  TC-BR-018 — Reset branding — 200

═══════════════════════════════════════════════════════════════════
  Part 3: Delegation Admin (TC-DA-001 … TC-DA-018)
═══════════════════════════════════════════════════════════════════
[20:02:38] PASS  TC-DA-001 — List permissions — 200
[20:02:38] PASS  TC-DA-002 — Permissions by category — 200
[20:02:38] PASS  TC-DA-003 — List role templates — 200
[20:02:38] PASS  TC-DA-004 — Create role template — 201
[20:02:38] PASS  TC-DA-005 — Get role template — 200
[20:02:38] PASS  TC-DA-006 — Update role template — 200
[20:02:38] PASS  TC-DA-007 — Create assignment — 201
[20:02:38] PASS  TC-DA-008 — List assignments — 200
[20:02:38] PASS  TC-DA-009 — Get assignment — 200
[20:02:38] PASS  TC-DA-010 — Get user permissions — 200
[20:02:38] PASS  TC-DA-011 — Check permission — 200
[20:02:38] PASS  TC-DA-012 — Get audit log — 200
[20:02:38] PASS  TC-DA-013 — Revoke assignment — 204
[20:02:38] PASS  TC-DA-014 — Empty permissions rejected — 422
[20:02:38] PASS  TC-DA-015 — Non-admin delegation — 403
[20:02:38] PASS  TC-DA-016 — No auth delegation — 401
[20:02:38] PASS  TC-DA-017 — Delete template — 204
[20:02:39] PASS  TC-DA-018 — Deleted template — 404

═══════════════════════════════════════════════════════════════════
  Part 4: Key Management (TC-KM-001 … TC-KM-008)
═══════════════════════════════════════════════════════════════════
[20:02:39] PASS  TC-KM-001 — List keys — 200
[20:02:42] PASS  TC-KM-002 — Rotate key — 200
[20:02:42] PASS  TC-KM-003 — List keys after rotation — 200
[20:02:42] PASS  TC-KM-004 — Revoke non-existent key — 404
[20:02:42] PASS  TC-KM-005 — Non-admin list keys — 403
[20:02:42] PASS  TC-KM-006 — Non-admin rotate key — 403
[20:02:42] PASS  TC-KM-007 — No auth list keys — 401
[20:02:42] PASS  TC-KM-008 — No auth rotate key — 401

═══════════════════════════════════════════════════════════════════
  Part 5: Admin Invitations (TC-AI-001 … TC-AI-012)
═══════════════════════════════════════════════════════════════════
[20:02:42] PASS  TC-AI-001 — List invitations — 200
[20:02:42] PASS  TC-AI-002 — Create invitation — 201
[20:02:42] PASS  TC-AI-003 — List invitations after create — 200
[20:02:42] PASS  TC-AI-004 — Resend invitation — 200
[20:02:42] PASS  TC-AI-005 — Invalid token — 400
[20:02:42] PASS  TC-AI-006 — Cancel invitation — 200
[20:02:42] PASS  TC-AI-007 — Non-admin create — 403
[20:02:42] PASS  TC-AI-008 — No auth list — 401
[20:02:42] PASS  TC-AI-009 — Duplicate invitation — 409
[20:02:42] PASS  TC-AI-010 — Resend non-existent — 404
[20:02:42] PASS  TC-AI-011 — Cancel non-existent — 404
[20:02:43] PASS  TC-AI-012 — Empty token — 422

═══════════════════════════════════════════════════════════════════
  Part 6: Org Security Policies (TC-OP-001 … TC-OP-015)
═══════════════════════════════════════════════════════════════════
[20:02:43] [info] Created org group bb748cf6-25f7-4235-afc3-eb0d211a0f9a
[20:02:43] PASS  TC-OP-001 — List org policies — 200
[20:02:43] PASS  TC-OP-002 — Create password policy — 201
[20:02:43] PASS  TC-OP-003 — Get password policy — 200
[20:02:43] PASS  TC-OP-004 — Update password policy — 200
[20:02:43] PASS  TC-OP-005 — Create MFA policy — 201
[20:02:43] PASS  TC-OP-006 — Create session policy — 201
[20:02:43] PASS  TC-OP-007 — Create IP policy — 201
[20:02:43] PASS  TC-OP-008 — Validate policy — 200
[20:02:43] PASS  TC-OP-009 — Effective org policy — 200
[20:02:43] PASS  TC-OP-010 — Effective user policy — 200
[20:02:43] PASS  TC-OP-011 — Delete policy — 204
[20:02:43] PASS  TC-OP-012 — Deleted policy — 404
[20:02:43] PASS  TC-OP-013 — Non-admin org policies — 200
[20:02:43] PASS  TC-OP-014 — No auth org policies — 401
[20:02:43] PASS  TC-OP-015 — Non-existent policy type — 400

═══════════════════════════════════════════════════════════════════
  Part 7: License Management (TC-LM-001 … TC-LM-030)
═══════════════════════════════════════════════════════════════════
[20:02:43] PASS  TC-LM-001 — List pools — 200
[20:02:44] PASS  TC-LM-002 — Create pool — 201
[20:02:44] PASS  TC-LM-003 — Get pool — 200
[20:02:44] PASS  TC-LM-004 — Update pool — 200
[20:02:44] PASS  TC-LM-005 — Create second pool — 201
[20:02:44] PASS  TC-LM-006 — Assign license — 201
[20:02:44] PASS  TC-LM-007 — List assignments — 200
[20:02:44] PASS  TC-LM-008 — Get assignment — 200
[20:02:44] PASS  TC-LM-009 — Deallocate license — 204
[20:02:44] PASS  TC-LM-010 — Bulk assign — 201
[20:02:44] PASS  TC-LM-011 — List entitlement links — 200
[20:02:44] PASS  TC-LM-012 — Create entitlement link — 201
[20:02:44] PASS  TC-LM-013 — Get link — 200
[20:02:44] PASS  TC-LM-014 — Toggle link enabled — 200
[20:02:44] PASS  TC-LM-015 — Delete link — 204
[20:02:44] PASS  TC-LM-016 — List incompatibilities — 200
[20:02:44] PASS  TC-LM-017 — Create incompatibility — 201
[20:02:44] PASS  TC-LM-018 — Get incompatibility — 200
[20:02:45] PASS  TC-LM-019 — Delete incompatibility — 204
[20:02:45] PASS  TC-LM-020 — List reclamation rules — 200
[20:02:45] PASS  TC-LM-021 — Create reclamation rule — 201
[20:02:45] PASS  TC-LM-022 — Get reclamation rule — 200
[20:02:45] PASS  TC-LM-023 — Update reclamation rule — 200
[20:02:45] PASS  TC-LM-024 — Delete reclamation rule — 204
[20:02:45] PASS  TC-LM-025 — Analytics dashboard — 200
[20:02:45] PASS  TC-LM-026 — Recommendations — 200
[20:02:45] PASS  TC-LM-027 — Expiring pools — 200
[20:02:45] PASS  TC-LM-028 — Compliance report — 200
[20:02:45] PASS  TC-LM-029 — Audit trail — 200
[20:02:45] PASS  TC-LM-030 — Archive pool — 200

═══════════════════════════════════════════════════════════════════
  Part 8: Escalation & Approval Groups (TC-ES-001 … TC-ES-020)
═══════════════════════════════════════════════════════════════════
[20:02:45] PASS  TC-ES-001 — List escalation policies — 200
[20:02:45] PASS  TC-ES-002 — Create escalation policy — 201
[20:02:45] PASS  TC-ES-003 — Get escalation policy — 200
[20:02:45] PASS  TC-ES-004 — Update escalation policy — 200
[20:02:45] PASS  TC-ES-005 — Add escalation level — 201
[20:02:45] PASS  TC-ES-006 — Add admin level — 201
[20:02:45] PASS  TC-ES-007 — Remove level — 204
[20:02:46] PASS  TC-ES-008 — Set default policy — 200
[20:02:46] PASS  TC-ES-009 — List escalation events — 200
[20:02:46] PASS  TC-ES-010 — List approval groups — 200
[20:02:46] PASS  TC-ES-011 — Create approval group — 201
[20:02:46] PASS  TC-ES-012 — Get approval group — 200
[20:02:46] PASS  TC-ES-013 — Update approval group — 200
[20:02:46] PASS  TC-ES-014 — Add members — 200
[20:02:46] PASS  TC-ES-015 — Remove members — 200
[20:02:46] PASS  TC-ES-016 — Enable group — 200
[20:02:46] PASS  TC-ES-017 — Disable group — 200
[20:02:46] PASS  TC-ES-018 — User approval groups — 200
[20:02:46] PASS  TC-ES-019 — Delete approval group — 204
[20:02:46] PASS  TC-ES-020 — Delete escalation policy — 204

═══════════════════════════════════════════════════════════════════
  Batch 11 Results: Admin Features & Governance Deep
═══════════════════════════════════════════════════════════════════

  PASS=136 FAIL=0 SKIP=0 TOTAL=136

  All tests passed!
═══════════════════════════════════════════════════════════════════
