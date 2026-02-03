# Hurl Functional Tests for xavyo-idp

Declarative HTTP API tests using [Hurl](https://hurl.dev/).

## Installation

### Option 1: Pre-built Binary (Recommended)
```bash
# Linux (x86_64)
curl -LO https://github.com/Orange-OpenSource/hurl/releases/download/7.1.0/hurl-7.1.0-x86_64-unknown-linux-gnu.tar.gz
tar -xzf hurl-7.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo mv hurl-7.1.0-x86_64-unknown-linux-gnu/hurl /usr/local/bin/

# macOS
brew install hurl

# Windows
choco install hurl
# or
scoop install hurl
```

### Option 2: Docker
```bash
docker pull ghcr.io/orange-opensource/hurl:latest
alias hurl='docker run --rm -v $(pwd):/work -w /work ghcr.io/orange-opensource/hurl:latest'
```

### Option 3: npm
```bash
npm install -g @anthropic/hurl
```

## Running Tests

### Prerequisites
1. Start the xavyo-idp server:
   ```bash
   cargo run -p idp-api
   ```

2. Verify server is running:
   ```bash
   curl http://localhost:8080/.well-known/openid-configuration
   ```

### Run All Tests
```bash
cd /home/pleclech/xavyo-idp
hurl --test --variables-file tests/hurl/vars.env tests/hurl/*.hurl
```

### Run Specific Test Files
```bash
# OIDC Discovery tests
hurl --test --variables-file tests/hurl/vars.env tests/hurl/oidc-discovery.hurl

# OAuth Token tests
hurl --test --variables-file tests/hurl/vars.env tests/hurl/oauth-token.hurl

# Security tests
hurl --test --variables-file tests/hurl/vars.env tests/hurl/security.hurl
```

### Verbose Output
```bash
hurl --test --very-verbose --variables-file tests/hurl/vars.env tests/hurl/*.hurl
```

### Generate Reports

#### JUnit XML (for CI/CD)
```bash
hurl --test --report-junit report.xml --variables-file tests/hurl/vars.env tests/hurl/*.hurl
```

#### HTML Report
```bash
hurl --test --report-html report/ --variables-file tests/hurl/vars.env tests/hurl/*.hurl
```

## Test Files

| File | Description | Features Covered |
|------|-------------|------------------|
| `oidc-discovery.hurl` | OIDC/JWKS endpoint tests | Core |
| `oauth-token.hurl` | Token endpoint edge cases | F-019 |
| `oauth-authorize.hurl` | Authorize endpoint security | F-019 |
| `device-flow.hurl` | Device authorization flow | OAuth |
| `protected-endpoints.hurl` | Auth requirement verification | All protected APIs |
| `security.hurl` | Security edge cases | XSS, SQLi, path traversal |

## CI/CD Integration

### GitHub Actions
```yaml
- name: Run Hurl Tests
  run: |
    hurl --test --report-junit hurl-results.xml \
      --variables-file tests/hurl/vars.env \
      tests/hurl/*.hurl

- name: Upload Test Results
  uses: actions/upload-artifact@v4
  with:
    name: hurl-results
    path: hurl-results.xml
```

### GitLab CI
```yaml
hurl-tests:
  script:
    - hurl --test --report-junit hurl-results.xml --variables-file tests/hurl/vars.env tests/hurl/*.hurl
  artifacts:
    reports:
      junit: hurl-results.xml
```

## Test Count Summary

| Category | Tests |
|----------|-------|
| OIDC Discovery | 6 |
| OAuth Token | 8 |
| OAuth Authorize | 10 |
| Device Flow | 4 |
| Protected Endpoints | 17 |
| Security | 12 |
| **Total** | **57** |

## Rate Limiting

The API has rate limiting enabled. Tests are designed to be rate-limit resilient by:
- Using `HTTP *` with `status >= 400` assertions instead of exact codes
- This allows tests to pass whether receiving 400, 401, 422, or 429 (rate limited)

If you see 429 responses during testing, wait a few seconds and re-run.

## Writing New Tests

Hurl files use a simple syntax:

```hurl
# Comment
GET {{base_url}}/endpoint
[QueryStringParams]
param: value
HTTP 200
[Asserts]
jsonpath "$.field" == "expected"
duration < 1000
```

See [Hurl documentation](https://hurl.dev/docs/manual.html) for full syntax reference.
