# Token Refresh Functional Tests

**API Endpoint**: `POST /auth/refresh`
**Authentication**: Refresh token (not JWT)
**Applicable Standards**: OAuth 2.0 (RFC 6749 Section 6), OWASP ASVS 3.5

---

## Nominal Cases

### TC-AUTH-REFRESH-001: Refresh access token with valid refresh token
- **Category**: Nominal
- **Input**:
  ```json
  POST /auth/refresh
  { "refresh_token": "<valid_refresh_token>" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "access_token": "<new_jwt>",
    "refresh_token": "<new_or_same_refresh_token>",
    "token_type": "Bearer",
    "expires_in": 3600
  }
  ```

### TC-AUTH-REFRESH-002: New access token has updated expiry
- **Category**: Nominal
- **Input**: Valid refresh
- **Expected Output**: New JWT `exp` > old JWT `exp`

### TC-AUTH-REFRESH-003: Refresh token rotation
- **Category**: Nominal
- **Standard**: OWASP ASVS 3.5.2
- **Input**: Valid refresh
- **Expected Output**: New refresh_token issued, old one invalidated

### TC-AUTH-REFRESH-004: User claims preserved in refreshed token
- **Category**: Nominal
- **Input**: Refresh after role change
- **Expected Output**: New JWT reflects current roles (not stale)

---

## Edge Cases

### TC-AUTH-REFRESH-010: Expired refresh token
- **Category**: Edge Case
- **Input**: Refresh token past its expiry
- **Expected Output**: Status 401 "Refresh token expired"

### TC-AUTH-REFRESH-011: Revoked refresh token
- **Category**: Edge Case
- **Preconditions**: Session revoked via logout
- **Input**: Use the revoked refresh token
- **Expected Output**: Status 401

### TC-AUTH-REFRESH-012: Reuse of rotated refresh token (replay detection)
- **Category**: Edge Case / Security
- **Standard**: OWASP ASVS 3.5.2
- **Preconditions**: Refresh token rotated (new one issued)
- **Input**: Use the old refresh token
- **Expected Output**: Status 401, AND all sessions for this user should be revoked (theft detection)

### TC-AUTH-REFRESH-013: Invalid refresh token format
- **Category**: Edge Case
- **Input**: `"refresh_token": "garbage"`
- **Expected Output**: Status 401

### TC-AUTH-REFRESH-014: Refresh with empty string
- **Category**: Edge Case
- **Input**: `"refresh_token": ""`
- **Expected Output**: Status 400

### TC-AUTH-REFRESH-015: Refresh for suspended user
- **Category**: Edge Case
- **Preconditions**: User suspended after token was issued
- **Input**: Valid refresh token for suspended user
- **Expected Output**: Status 401 (no new tokens issued)

### TC-AUTH-REFRESH-016: Refresh for deleted user
- **Category**: Edge Case
- **Input**: Refresh token for deleted user
- **Expected Output**: Status 401

### TC-AUTH-REFRESH-017: Concurrent refresh requests with same token
- **Category**: Edge Case
- **Input**: Two simultaneous refresh requests with same token
- **Expected Output**: Exactly one succeeds, other fails (no double-issue)

---

## Security Cases

### TC-AUTH-REFRESH-020: Refresh token bound to session
- **Category**: Security
- **Verification**: Refresh token is linked to a specific session in DB

### TC-AUTH-REFRESH-021: Refresh token has bounded lifetime
- **Category**: Security
- **Verification**: Refresh token expiry is <= 30 days (or configured policy)

### TC-AUTH-REFRESH-022: Refresh does not extend refresh token lifetime
- **Category**: Security
- **Verification**: New refresh token has same or earlier absolute expiry as original session

### TC-AUTH-REFRESH-023: Rate limiting on refresh endpoint
- **Category**: Security
- **Input**: 50 rapid refresh requests
- **Expected Output**: Rate limiting applied
