#!/usr/bin/env bash
# =============================================================================
# Run All Functional Test Batches — Comprehensive Test Suite
# =============================================================================
# Executes all 13 test batches sequentially and produces a combined report.
#
# Prerequisites:
#   - API server running on localhost:8080
#   - PostgreSQL with migrations applied
#   - Mailpit running on localhost:8025
#
# Domains covered:
#   Batch 1: auth (signup, login, password reset, email verification, token refresh)
#   Batch 2: users, groups, sessions
#   Batch 3: oauth, mfa, policies, tenants
#   Batch 4: scim, api-keys, connectors, webhooks
#   Batch 5: oidc, saml, social
#   Batch 6: governance, agents (NHI), operations, gdpr
#   Batch 7: import-export, invitations
#   Batch 8: deep NHI creds/tools/certs, governance SoD/certs/access-requests, SCIM deep
#   Batch 9: governance deep (role mining, merge, personas, risk)
#   Batch 10: infrastructure & self-service (/me, devices, audit, alerts, authz, system)
#   Batch 11: admin features (IP, branding, delegation, keys, invitations, org policies, license, escalation)
#   Batch 12: connectors deep (SCIM outbound, reconciliation, DLQ, circuit breakers, jobs, health, sync)
#   Batch 13: NHI Feature 201 (unified model, lifecycle, certification, permissions, risk, inactivity, SoD)
#   Batch 14: Features 202-205 (API key identity, NHI permissions, protocol migration)
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT="$SCRIPT_DIR/all-batches-results.md"
TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_SKIP=0; TOTAL_TESTS=0
BATCH_RESULTS=()

# Clear Mailpit inbox
curl -s -X DELETE http://localhost:8025/api/v1/messages > /dev/null 2>&1

# Health check
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health | grep -q "200"; then
  echo "ERROR: API server not responding on http://localhost:8080/health"
  exit 1
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "  Running All Functional Test Batches — $(date)"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Initialize combined report
cat > "$REPORT" << 'EOF'
# Functional Test Suite — Combined Results

| Batch | Domain | Pass | Fail | Skip | Total |
|-------|--------|------|------|------|-------|
EOF

BATCHES=(
  "run-batch-1-auth.sh|Auth"
  "run-batch-2-users-groups-sessions.sh|Users+Groups+Sessions"
  "run-batch-3-oauth-mfa-policies-tenants.sh|OAuth+MFA+Policies+Tenants"
  "run-batch-4-scim-apikeys-connectors-webhooks.sh|SCIM+APIKeys+Connectors+Webhooks"
  "run-batch-5-oidc-saml-social.sh|OIDC+SAML+Social"
  "run-batch-6-governance-nhi-ops.sh|Governance+NHI+Ops+GDPR"
  "run-batch-7-import-export.sh|Import+Export+Invitations"
  "run-batch-8-deep-nhi-gov-scim.sh|Deep NHI+Governance+SCIM"
  "run-batch-9-governance-deep.sh|Governance Deep (Mining+Merge+Personas+Risk)"
  "run-batch-10-infra-selfservice.sh|Infra+Self-Service"
  "run-batch-11-admin-governance-deep.sh|Admin+Gov Deep (IP+Branding+Delegation+Keys+Escalation)"
  "run-batch-12-connectors-webhooks-deep.sh|Connectors Deep+Webhooks Deep"
  "run-batch-13-nhi-201-unified.sh|NHI Feature 201 (Unified+Lifecycle+Cert+Perms+Risk+SoD)"
  "run-batch-14-features-202-205.sh|Features 202-205 (APIKey+NHI Perms+Protocols)"
)

for i in "${!BATCHES[@]}"; do
  IFS="|" read -r script domain <<< "${BATCHES[$i]}"
  batch_num=$((i + 1))
  script_path="$SCRIPT_DIR/$script"

  if [[ ! -f "$script_path" ]]; then
    echo "WARNING: $script not found, skipping"
    continue
  fi

  echo "───────────────────────────────────────────────────────────────────"
  echo "  Batch $batch_num: $domain"
  echo "───────────────────────────────────────────────────────────────────"

  # Clear emails between batches
  curl -s -X DELETE http://localhost:8025/api/v1/messages > /dev/null 2>&1

  # Run the batch and capture output
  OUTPUT=$(bash "$script_path" 2>&1)
  EXIT_CODE=$?

  # Extract results — handle multiple summary formats:
  # Format A: "PASS=$N FAIL=$N SKIP=$N TOTAL=$N" (batches 4-7)
  # Format B: "Total: $N  Pass: $N  Fail: $N  Skip: $N" (batches 1-2)
  # Format C: "Total: $N | Pass: $N | Fail: $N | Skip: $N" (batch 3)
  B_PASS=0; B_FAIL=0; B_SKIP=0; B_TOTAL=0

  SUMMARY_A=$(echo "$OUTPUT" | grep -E "PASS=[0-9]+ FAIL=[0-9]+ SKIP=[0-9]+ TOTAL=[0-9]+" | tail -1)
  SUMMARY_B=$(echo "$OUTPUT" | grep -E "Total: [0-9]+" | tail -1)

  if [[ -n "$SUMMARY_A" ]]; then
    B_PASS=$(echo "$SUMMARY_A" | grep -oP 'PASS=\K[0-9]+' | tail -1)
    B_FAIL=$(echo "$SUMMARY_A" | grep -oP 'FAIL=\K[0-9]+' | tail -1)
    B_SKIP=$(echo "$SUMMARY_A" | grep -oP 'SKIP=\K[0-9]+' | tail -1)
    B_TOTAL=$(echo "$SUMMARY_A" | grep -oP 'TOTAL=\K[0-9]+' | tail -1)
  elif [[ -n "$SUMMARY_B" ]]; then
    B_TOTAL=$(echo "$SUMMARY_B" | grep -oP 'Total:\s*\K[0-9]+' | tail -1)
    B_PASS=$(echo "$SUMMARY_B" | grep -oP 'Pass:\s*\K[0-9]+' | tail -1)
    B_FAIL=$(echo "$SUMMARY_B" | grep -oP 'Fail:\s*\K[0-9]+' | tail -1)
    B_SKIP=$(echo "$SUMMARY_B" | grep -oP 'Skip:\s*\K[0-9]+' | tail -1)
  else
    # Fallback: count PASS/FAIL/SKIP lines
    B_PASS=$(echo "$OUTPUT" | grep -c "PASS " || true)
    B_FAIL=$(echo "$OUTPUT" | grep -c "FAIL " || true)
    B_SKIP=$(echo "$OUTPUT" | grep -c "SKIP " || true)
    B_TOTAL=$((B_PASS + B_FAIL + B_SKIP))
  fi

  # Ensure numeric (default to 0 if empty)
  B_PASS=${B_PASS:-0}; B_FAIL=${B_FAIL:-0}; B_SKIP=${B_SKIP:-0}; B_TOTAL=${B_TOTAL:-0}

  TOTAL_PASS=$((TOTAL_PASS + B_PASS))
  TOTAL_FAIL=$((TOTAL_FAIL + B_FAIL))
  TOTAL_SKIP=$((TOTAL_SKIP + B_SKIP))
  TOTAL_TESTS=$((TOTAL_TESTS + B_TOTAL))

  STATUS="PASS"
  [[ "$B_FAIL" -gt 0 ]] && STATUS="FAIL"

  echo "  Result: $B_PASS pass, $B_FAIL fail, $B_SKIP skip ($B_TOTAL total)"
  echo "| $batch_num | $domain | $B_PASS | $B_FAIL | $B_SKIP | $B_TOTAL |" >> "$REPORT"

  BATCH_RESULTS+=("Batch $batch_num ($domain): $STATUS — $B_PASS/$B_TOTAL")

  # Show failures if any
  if [[ "$B_FAIL" -gt 0 ]]; then
    echo ""
    echo "  FAILURES:"
    echo "$OUTPUT" | grep "FAIL " | head -20
    echo ""
  fi
done

# Write totals
echo "| **TOTAL** | **All domains** | **$TOTAL_PASS** | **$TOTAL_FAIL** | **$TOTAL_SKIP** | **$TOTAL_TESTS** |" >> "$REPORT"
echo "" >> "$REPORT"
echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  FINAL RESULTS — All Batches"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
for result in "${BATCH_RESULTS[@]}"; do
  echo "  $result"
done
echo ""
echo "  TOTAL: PASS=$TOTAL_PASS FAIL=$TOTAL_FAIL SKIP=$TOTAL_SKIP TOTAL=$TOTAL_TESTS"
echo ""
echo "═══════════════════════════════════════════════════════════════════"

if [[ "$TOTAL_FAIL" -eq 0 ]]; then
  echo "  All tests passed!"
else
  echo "  SOME TESTS FAILED — see individual batch results for details"
fi
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Report written to: $REPORT"
