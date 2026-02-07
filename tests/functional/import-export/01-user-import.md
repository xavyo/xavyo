# Bulk User Import Functional Tests

**API Endpoints**:
- `POST /admin/users/import` (upload CSV file for import)
- `GET /admin/users/imports` (list import jobs)
- `GET /admin/users/imports/:job_id` (get import job status)
- `GET /admin/users/imports/:job_id/errors` (list import errors)
- `GET /admin/users/imports/:job_id/errors/download` (download error CSV)
- `POST /admin/users/imports/:job_id/resend-invitations` (resend invitations for imported users)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: Data quality validation, GDPR Article 5 (data accuracy), CSV injection prevention

---

## Nominal Cases

### TC-IMPORT-USER-001: Import valid CSV with all fields
- **Category**: Nominal
- **Preconditions**: Authenticated admin
- **Input**:
  ```
  POST /admin/users/import
  Content-Type: multipart/form-data
  File: users.csv containing:
    email,display_name,department,role
    alice@example.com,Alice Smith,Engineering,user
    bob@example.com,Bob Jones,Marketing,user
    carol@example.com,Carol White,HR,admin
  ```
- **Expected Output**:
  ```
  Status: 202 Accepted
  Body: {
    "job_id": "<uuid>",
    "status": "processing",
    "total_rows": 3,
    "created_at": "2026-02-07T..."
  }
  ```
- **Side Effects**:
  - Import job queued for async processing
  - Audit log: `import.job.created`

### TC-IMPORT-USER-002: Get import job status (completed)
- **Category**: Nominal
- **Preconditions**: Import job has completed
- **Input**: `GET /admin/users/imports/:job_id`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "job_id": "<uuid>",
    "status": "completed",
    "total_rows": 3,
    "successful": 3,
    "failed": 0,
    "skipped": 0,
    "started_at": "2026-02-07T10:00:00Z",
    "completed_at": "2026-02-07T10:00:05Z"
  }
  ```

### TC-IMPORT-USER-003: List all import jobs
- **Category**: Nominal
- **Preconditions**: 3 import jobs have been run
- **Input**: `GET /admin/users/imports`
- **Expected Output**: Status 200, array of 3 job summaries ordered by creation date

### TC-IMPORT-USER-004: Import CSV with minimal required fields
- **Category**: Nominal
- **Input**: CSV with only `email` column:
  ```
  email
  user1@example.com
  user2@example.com
  ```
- **Expected Output**: Status 202, users created with email only (display_name auto-generated or null)

### TC-IMPORT-USER-005: Import creates users with correct tenant
- **Category**: Nominal
- **Verification**: All imported users have `tenant_id` matching the admin's tenant

### TC-IMPORT-USER-006: Resend invitations for imported users
- **Category**: Nominal
- **Preconditions**: Import job completed with 3 users, invitations not yet sent
- **Input**: `POST /admin/users/imports/:job_id/resend-invitations`
- **Expected Output**: Status 200, invitations queued for all imported users
- **Side Effects**: Verification/welcome emails sent

### TC-IMPORT-USER-007: Import with partial failures
- **Category**: Nominal
- **Input**: CSV with 5 rows, 2 with invalid emails:
  ```
  email,display_name
  valid1@example.com,User 1
  invalid-email,User 2
  valid2@example.com,User 3
  also-invalid,User 4
  valid3@example.com,User 5
  ```
- **Expected Output**: Job completes with `successful: 3, failed: 2`
- **Verification**: Valid users created, errors recorded for invalid rows

### TC-IMPORT-USER-008: List import errors
- **Category**: Nominal
- **Preconditions**: Import job with 2 failures
- **Input**: `GET /admin/users/imports/:job_id/errors`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "errors": [
      { "row": 2, "field": "email", "value": "invalid-email", "error": "Invalid email format" },
      { "row": 4, "field": "email", "value": "also-invalid", "error": "Invalid email format" }
    ]
  }
  ```

### TC-IMPORT-USER-009: Download error CSV
- **Category**: Nominal
- **Input**: `GET /admin/users/imports/:job_id/errors/download`
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: text/csv
  Content-Disposition: attachment; filename="import-errors-<job_id>.csv"
  ```

---

## Edge Cases

### TC-IMPORT-USER-010: Import empty CSV (header only)
- **Category**: Edge Case
- **Input**: CSV with only header row, no data
- **Expected Output**: Status 400 "No data rows in CSV" OR Status 202 with 0 processed

### TC-IMPORT-USER-011: Import CSV with no header
- **Category**: Edge Case
- **Input**: CSV without header row
- **Expected Output**: Status 400 "Missing CSV header"

### TC-IMPORT-USER-012: Import CSV with duplicate emails
- **Category**: Edge Case
- **Input**: CSV with same email appearing twice
- **Expected Output**: First row succeeds, second row fails with "Duplicate email"

### TC-IMPORT-USER-013: Import user with email already in system
- **Category**: Edge Case
- **Preconditions**: alice@example.com already exists
- **Input**: CSV containing alice@example.com
- **Expected Output**: Row skipped/failed with "User already exists"

### TC-IMPORT-USER-014: Import very large CSV (10,000 rows)
- **Category**: Edge Case
- **Input**: CSV with 10,000 valid rows
- **Expected Output**: Status 202, job processes asynchronously
- **Verification**: All 10,000 users created (may take time)

### TC-IMPORT-USER-015: Import CSV exceeding maximum file size
- **Category**: Edge Case
- **Input**: CSV file larger than max upload limit (e.g., 50 MB)
- **Expected Output**: Status 413 "File too large"

### TC-IMPORT-USER-016: Import CSV with wrong file type
- **Category**: Edge Case
- **Input**: Upload a `.json` or `.xlsx` file instead of CSV
- **Expected Output**: Status 400 "Invalid file format, CSV expected"

### TC-IMPORT-USER-017: Import CSV with extra unknown columns
- **Category**: Edge Case
- **Input**: CSV with `email,display_name,favorite_color` (unknown column)
- **Expected Output**: Status 202, unknown columns ignored, users created from known columns

### TC-IMPORT-USER-018: Import with unicode in display_name
- **Category**: Edge Case
- **Input**: CSV containing: `user@example.com,"Jean-Pierre Leveque"`
- **Expected Output**: Display name stored correctly with special characters

### TC-IMPORT-USER-019: Get status of non-existent job
- **Category**: Edge Case
- **Input**: `GET /admin/users/imports/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404 "Import job not found"

---

## Security Cases

### TC-IMPORT-USER-020: CSV injection prevention
- **Category**: Security
- **Standard**: CWE-1236
- **Input**: CSV with formula injection:
  ```
  email,display_name
  user@example.com,"=CMD('calc')"
  ```
- **Expected Output**: Formula prefix stripped or escaped. Display name stored as literal string, not executed.

### TC-IMPORT-USER-021: Non-admin cannot import users
- **Category**: Security
- **Input**: Regular user calls `POST /admin/users/import`
- **Expected Output**: Status 403 Forbidden

### TC-IMPORT-USER-022: Cross-tenant import isolation
- **Category**: Security
- **Preconditions**: Admin of tenant A
- **Verification**: Imported users are ONLY created in tenant A, never in another tenant

### TC-IMPORT-USER-023: Imported passwords are properly hashed
- **Category**: Security
- **Input**: CSV with `password` column (if supported)
- **Expected Output**: Passwords stored as Argon2id hashes, never plaintext

### TC-IMPORT-USER-024: Error CSV does not leak sensitive data
- **Category**: Security
- **Input**: `GET /admin/users/imports/:job_id/errors/download`
- **Expected Output**: Error CSV contains row number and field errors, NOT other users' data

### TC-IMPORT-USER-025: Filename sanitization
- **Category**: Security
- **Standard**: CWE-22 (Path Traversal)
- **Input**: Upload file named `../../etc/passwd.csv`
- **Expected Output**: Filename sanitized; no path traversal vulnerability
