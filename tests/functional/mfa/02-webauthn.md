# WebAuthn / FIDO2 Functional Tests

**API Endpoints**:
- `POST /auth/mfa/webauthn/register/begin` (start registration)
- `POST /auth/mfa/webauthn/register/complete` (finish registration)
- `POST /auth/mfa/webauthn/authenticate/begin` (start authentication)
- `POST /auth/mfa/webauthn/authenticate/complete` (finish authentication)
- `GET /me/passkeys` (list registered credentials)
- `DELETE /me/passkeys/:id` (remove credential)
**Authentication**: JWT (Bearer token)
**Applicable Standards**: W3C WebAuthn Level 2, FIDO2, NIST SP 800-63B AAL2/AAL3

---

## Nominal Cases

### TC-MFA-WEBAUTHN-001: Begin passkey registration
- **Category**: Nominal
- **Input**: `POST /auth/mfa/webauthn/register/begin`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "publicKey": {
      "rp": { "name": "xavyo", "id": "<domain>" },
      "user": { "id": "<base64>", "name": "<email>", "displayName": "<name>" },
      "challenge": "<base64url>",
      "pubKeyCredParams": [...],
      "timeout": 60000,
      "attestation": "none",
      "authenticatorSelection": { ... }
    }
  }
  ```

### TC-MFA-WEBAUTHN-002: Complete passkey registration
- **Category**: Nominal
- **Input**: `POST /auth/mfa/webauthn/register/complete` with attestation response
- **Expected Output**: Status 200, credential stored
- **Side Effects**: Passkey record in DB, audit log `mfa.webauthn.registered`

### TC-MFA-WEBAUTHN-003: Authenticate with registered passkey
- **Category**: Nominal
- **Input**:
  1. `POST /auth/mfa/webauthn/authenticate/begin` → challenge
  2. `POST /auth/mfa/webauthn/authenticate/complete` with assertion response
- **Expected Output**: Status 200, authentication successful

### TC-MFA-WEBAUTHN-004: List registered passkeys
- **Category**: Nominal
- **Input**: `GET /me/passkeys`
- **Expected Output**: Array of credentials with id, name, created_at (no private keys)

### TC-MFA-WEBAUTHN-005: Remove a passkey
- **Category**: Nominal
- **Input**: `DELETE /me/passkeys/:id`
- **Expected Output**: Status 200 (or 204)

### TC-MFA-WEBAUTHN-006: Multiple passkeys per user
- **Category**: Nominal
- **Input**: Register 3 different passkeys
- **Expected Output**: All 3 listed, any can be used for authentication

---

## Edge Cases

### TC-MFA-WEBAUTHN-010: Registration with expired challenge
- **Category**: Edge Case
- **Input**: Complete registration after challenge timeout (>60s)
- **Expected Output**: Status 400 "Challenge expired"

### TC-MFA-WEBAUTHN-011: Registration with wrong challenge
- **Category**: Edge Case
- **Input**: Complete registration with mismatched challenge
- **Expected Output**: Status 400

### TC-MFA-WEBAUTHN-012: Replay of registration response
- **Category**: Edge Case / Security
- **Input**: Submit same attestation response twice
- **Expected Output**: Second submission fails

### TC-MFA-WEBAUTHN-013: Authentication with unregistered credential
- **Category**: Edge Case
- **Input**: Assert with credential ID not in database
- **Expected Output**: Status 401

### TC-MFA-WEBAUTHN-014: Delete last passkey when MFA required
- **Category**: Edge Case
- **Preconditions**: Tenant requires MFA, only 1 passkey registered, no TOTP
- **Input**: `DELETE /me/passkeys/:id`
- **Expected Output**: Status 403 "Cannot remove last MFA method"

### TC-MFA-WEBAUTHN-015: Registration challenge is single-use
- **Category**: Edge Case
- **Input**: Use same begin-registration response for two complete calls
- **Expected Output**: Second call fails

### TC-MFA-WEBAUTHN-016: Signature counter validation
- **Category**: Edge Case / Security
- **Standard**: WebAuthn spec Section 7.2 Step 17
- **Input**: Assert with signature counter <= stored counter
- **Expected Output**: Status 401 (possible cloned authenticator)

---

## Security Cases

### TC-MFA-WEBAUTHN-020: Challenge is cryptographically random
- **Category**: Security
- **Verification**: Challenge has >= 16 bytes of entropy (WebAuthn spec)

### TC-MFA-WEBAUTHN-021: RP ID matches server origin
- **Category**: Security
- **Verification**: `rp.id` in registration options matches server domain

### TC-MFA-WEBAUTHN-022: Credential private key never exposed
- **Category**: Security
- **Verification**: DB stores public key only; `GET /me/passkeys` returns no key material

### TC-MFA-WEBAUTHN-023: User verification flag respected
- **Category**: Security
- **Standard**: WebAuthn Level 2
- **Verification**: If UV required, assertion with UV=false is rejected

### TC-MFA-WEBAUTHN-024: Cross-origin registration prevented
- **Category**: Security
- **Input**: Registration from different origin than RP ID
- **Expected Output**: Rejected

### TC-MFA-WEBAUTHN-025: Attestation validation
- **Category**: Security
- **Verification**: Server validates attestation format (none, packed, fido-u2f, etc.)
