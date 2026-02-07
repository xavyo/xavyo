# Batch 5: OIDC · SAML · Social — Functional Test Results

**Date**: 2026-02-07T17:50:59+00:00
**Server**: http://localhost:8080

## Summary

PASS=102 FAIL=0 SKIP=7 TOTAL=109

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-OIDC-DISC-001 | PASS | 200, issuer=http://localhost:8080 |
| TC-OIDC-DISC-002 | PASS | issuer=http://localhost:8080 matches http://localhost:8080 |
| TC-OIDC-DISC-003 | PASS | 200, keys=1 |
| TC-OIDC-DISC-004 | PASS | keys=1 (>=1) |
| TC-OIDC-DISC-005 | PASS | device_authorization_endpoint=http://localhost:8080/oauth/device/code |
| TC-OIDC-DISC-006 | PASS | S256 in code_challenge_methods_supported |
| TC-OIDC-DISC-007 | PASS | n and e are valid base64url |
| TC-OIDC-DISC-008 | PASS | No Cache-Control (acceptable, response is static) |
| TC-OIDC-DISC-010 | PASS | 200, JSON returned despite Accept: XML |
| TC-OIDC-DISC-011 | PASS | 405, POST rejected |
| TC-OIDC-DISC-012 | PASS | 405, POST rejected |
| TC-OIDC-DISC-014 | PASS | 200, query params ignored |
| TC-OIDC-DISC-016 | PASS | jwks_uri=http://localhost:8080/.well-known/jwks.json |
| TC-OIDC-DISC-017 | PASS | All endpoint URLs are absolute |
| TC-OIDC-DISC-018 | PASS | All required arrays are non-empty |
| TC-OIDC-DISC-019 | PASS | All 1 kid values are unique |
| TC-OIDC-DISC-020 | PASS | No internal details leaked |
| TC-OIDC-DISC-021 | PASS | No private key material in JWKS |
| TC-OIDC-DISC-022 | PASS | Security headers present |
| TC-OIDC-DISC-024 | PASS | No CORS wildcard |
| TC-OIDC-DISC-030 | PASS | All required OIDC Discovery fields present |
| TC-OIDC-DISC-031 | PASS | issuer=http://localhost:8080 (HTTPS or localhost) |
| TC-OIDC-DISC-032 | PASS | issuer has no trailing slash |
| TC-OIDC-DISC-033 | PASS | openid in scopes_supported |
| TC-OIDC-DISC-034 | PASS | code in response_types_supported |
| TC-OIDC-DISC-035 | PASS | public in subject_types_supported |
| TC-OIDC-DISC-036 | PASS | RS256 in id_token_signing_alg_values_supported |
| TC-OIDC-DISC-037 | PASS | All mandatory claims (sub,iss,aud,exp,iat) present |
| TC-OIDC-DISC-038 | PASS | token_endpoint_auth_methods_supported=[
  "client_secret_basic",
  "client_secret_post"
] |
| TC-OIDC-DISC-039 | PASS | JWK has kty=RSA, kid=primary, use=sig |
| TC-OIDC-UI-001 | PASS | 403, openid scope required (correct for login JWT) |
| TC-OIDC-UI-010 | PASS | 401, no auth header |
| TC-OIDC-UI-011 | PASS | 401, Basic auth rejected |
| TC-OIDC-UI-012 | PASS | 401, empty Bearer token |
| TC-OIDC-UI-013 | PASS | 401, expired/invalid token |
| TC-OIDC-UI-014 | PASS | 401, malformed JWT |
| TC-OIDC-UI-017 | PASS | 405, POST not allowed |
| TC-OIDC-UI-020 | PASS | 403, insufficient scope: Insufficient scope: The access token must have openid scope for userinfo |
| TC-OIDC-UI-022 | PASS | No sensitive fields in response |
| TC-OIDC-UI-024 | PASS | No CORS wildcard |
| TC-OIDC-IDT-008 | SKIP | No OAuth client |
| TC-OIDC-IDT-029 | SKIP | No OAuth client |
| TC-OIDC-IDT-030 | SKIP | No OAuth client |
| TC-OIDC-IDT-040 | PASS | JWT alg=RS256 |
| TC-OIDC-IDT-050 | PASS | JWT has 3 parts |
| TC-OIDC-IDT-051 | PASS | Header has alg=RS256, typ=JWT |
| TC-OIDC-IDT-052 | PASS | sub=8effb017-cad1-4fa9-86c8-1fd05e0b0bd1 (UUID) |
| TC-OIDC-IDT-054 | PASS | exp=1770487562, iat=1770486662 (numeric) |
| TC-OIDC-IDT-055 | SKIP | No OAuth client |
| TC-OIDC-IDT-056 | SKIP | No OAuth client |
| TC-OIDC-IDT-057 | SKIP | No OAuth client |
| TC-OIDC-IDT-058 | SKIP | No OAuth client |
| TC-OIDC-FED-001 | PASS | 200, authentication_method=standard |
| TC-OIDC-FED-002 | PASS | 200, standard for unknown domain |
| TC-OIDC-FED-025 | PASS | 400, non-existent IdP rejected |
| TC-OIDC-FED-029 | PASS | 400, invalid email rejected |
| TC-OIDC-FED-040 | PASS | 400, missing state parameter |
| TC-OIDC-FED-021 | PASS | 401, unknown state rejected |
| TC-OIDC-FED-022 | PASS | 400, IdP error handled |
| TC-OIDC-FED-023 | PASS | 400, no code or error |
| TC-SAML-META-001 | PASS | 200, EntityDescriptor present |
| TC-SAML-META-003 | PASS | Both HTTP-Redirect and HTTP-POST bindings present |
| TC-SAML-META-004 | PASS | 201, sp_id=a4ec58df-aea3-4401-85af-0565dd65676e |
| TC-SAML-META-005 | PASS | 201, minimal SP created |
| TC-SAML-META-007 | PASS | 200, total=7 |
| TC-SAML-META-009 | PASS | 200, name=Batch5 SP 1770486659 |
| TC-SAML-META-010 | PASS | 200, SP updated |
| TC-SAML-META-014 | PASS | 409, duplicate entity_id rejected |
| TC-SAML-META-015 | PASS | 400, empty acs_urls rejected |
| TC-SAML-META-016 | PASS | 404, nonexistent SP |
| TC-SAML-META-017 | PASS | 404, delete nonexistent SP |
| TC-SAML-META-023 | PASS | 401, unauthenticated |
| TC-SAML-META-024 | PASS | 200, read access allowed for non-admin |
| TC-SAML-META-029 | PASS | Content-Type: content-type: application/xml; charset=utf-8 |
| TC-SAML-META-031 | PASS | SAML 2.0 metadata namespace present |
| TC-SAML-META-032 | PASS | SAML 2.0 protocol enumeration present |
| TC-SAML-META-033 | PASS | 3 NameID format(s) advertised |
| TC-SAML-META-035 | PASS | Well-formed XML |
| TC-SAML-META-011 | PASS | 204, SP deleted |
| TC-SAML-CERT-003 | PASS | 200, certificates=0 |
| TC-SAML-CERT-014 | PASS | 400, empty certificate rejected |
| TC-SAML-CERT-015 | PASS | 400, empty private_key rejected |
| TC-SAML-CERT-016 | PASS | 422, missing fields rejected |
| TC-SAML-CERT-017 | PASS | 404, nonexistent certificate |
| TC-SAML-CERT-023 | PASS | No private key in list response |
| TC-SAML-CERT-027 | PASS | 401, unauthenticated |
| TC-SAML-CERT-028 | PASS | 422, validation before admin check (permissive) |
| TC-SAML-CERT-029 | PASS | No key material in error response |
| TC-SAML-SSO-015 | PASS | 400, unknown SP rejected |
| TC-SAML-SSO-019 | PASS | 400, empty issuer rejected |
| TC-SAML-SSO-022 | PASS | 400, malformed base64 rejected |
| TC-SAML-SSO-027 | PASS | 400, unauthenticated SSO handled |
| TC-SAML-SSO-034 | PASS | No internal details leaked |
| TC-SAML-IDP-011 | PASS | 401, nonexistent SP (auth-first pattern) |
| TC-SAML-IDP-012 | PASS | 400, invalid UUID rejected |
| TC-SAML-IDP-020 | PASS | 401, unauthenticated |
| TC-SAML-IDP-023 | PASS | 401, expired JWT rejected |
| TC-SAML-IDP-026 | PASS | No internal details leaked |
| TC-SAML-SLO-011 | PASS | 401, invalid SLO request handled |
| TC-SAML-SLO-021 | PASS | 401, cross-tenant SLO blocked |
| TC-SOCIAL-PROV-001 | PASS | 200, social providers listed |
| TC-SOCIAL-PROV-002 | PASS | 200, Google provider configured |
| TC-SOCIAL-PROV-005 | PASS | 403, provider not configured (expected) |
| TC-SOCIAL-PROV-006 | PASS | 403, provider not configured (expected) |
| TC-SOCIAL-PROV-011 | PASS | 400, invalid state rejected |
| TC-SOCIAL-PROV-013 | PASS | 307, redirects to frontend with error param |
| TC-SOCIAL-PROV-015 | PASS | 400, unconfigured provider rejected |
| TC-SOCIAL-PROV-021 | PASS | 400, missing code handled |
| TC-SOCIAL-PROV-025 | PASS | 403, cross-tenant blocked |
