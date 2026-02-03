# OpenID Connect Conformance Testing for xavyo-idp

Testing suite for validating xavyo-idp's OIDC implementation against the [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) specification.

## Quick Validation (Local)

Use Hurl for quick OIDC spec validation:

```bash
# Run OIDC Core specification tests
cd tests/hurl
hurl --test --variables-file vars.env oidc-core-spec.hurl

# Run all functional tests (81 tests)
hurl --test --variables-file vars.env *.hurl
```

## Official Certification

For official OpenID certification, use the [OpenID Foundation Conformance Suite](https://openid.net/certification/about-conformance-suite/).

## Overview

The OpenID Conformance Suite tests your OpenID Connect implementation against the official specifications:

- **OpenID Connect Core 1.0** - Basic, Implicit, Hybrid profiles
- **OpenID Connect Discovery 1.0**
- **OpenID Connect Dynamic Client Registration 1.0**
- **OAuth 2.0 RFC 6749**
- **PKCE RFC 7636**

## Prerequisites

1. Docker and Docker Compose installed
2. xavyo-idp server running on `localhost:8080`
3. PostgreSQL database accessible

## Quick Start

### 1. Setup Test Clients in Database

```bash
# Connect to your PostgreSQL database and run:
psql -h localhost -U xavyo -d xavyo_test -f setup-test-clients.sql
```

Or via Docker:
```bash
docker exec -i xavyo-postgres psql -U xavyo -d xavyo_test < setup-test-clients.sql
```

### 2. Start the Conformance Suite

```bash
cd tests/oidc-conformance
docker-compose up -d
```

### 3. Access the Web Interface

Open https://localhost:8443 in your browser (accept the self-signed certificate).

### 4. Create a Test Plan

1. Click "Create a new test plan"
2. Select **"OpenID Connect Core: Basic Certification Profile Authorization server test"**
3. Configure:
   - **Alias**: `xavyo-idp`
   - **Discovery URL**: `http://host.docker.internal:8080/.well-known/openid-configuration`
   - **Client ID**: `conformance-test-client-1`
   - **Client Secret**: `conformance-test-secret-1`
   - **Client Authentication**: `client_secret_basic`

### 5. Run Tests

Click "Start Test Plan" and follow the prompts.

## Test Plans Available

| Plan | Description | Profile |
|------|-------------|---------|
| `oidcc-basic-certification-test-plan` | Basic profile certification | OP |
| `oidcc-implicit-certification-test-plan` | Implicit flow certification | OP |
| `oidcc-hybrid-certification-test-plan` | Hybrid flow certification | OP |
| `oidcc-formpost-basic-certification-test-plan` | Form POST response mode | OP |
| `oidcc-dynamic-certification-test-plan` | Dynamic registration | OP |

## Configuration

### Environment Variables

Create a `.env` file:

```bash
# Test Client Credentials
OIDC_TEST_CLIENT_ID=conformance-test-client-1
OIDC_TEST_CLIENT_SECRET=conformance-test-secret-1
OIDC_TEST_CLIENT2_ID=conformance-test-client-2
OIDC_TEST_CLIENT2_SECRET=conformance-test-secret-2

# xavyo-idp Server
XAVYO_IDP_URL=http://host.docker.internal:8080
```

### Test Credentials

| Type | ID | Secret |
|------|-----|--------|
| Client 1 | `conformance-test-client-1` | `conformance-test-secret-1` |
| Client 2 | `conformance-test-client-2` | `conformance-test-secret-2` |
| User | `conformance-test-user` | `conformance-test-password` |

## CI/CD Integration

### Python API for Automated Testing

The conformance suite provides a Python API for CI/CD integration:

```bash
pip install conformance-suite-api
```

```python
from conformance_suite import ConformanceSuiteAPI

api = ConformanceSuiteAPI("https://localhost:8443")

# Create test plan
plan_id = api.create_plan(
    plan_name="oidcc-basic-certification-test-plan",
    configuration={
        "alias": "xavyo-idp-ci",
        "server": {
            "discoveryUrl": "http://host.docker.internal:8080/.well-known/openid-configuration"
        },
        "client": {
            "client_id": "conformance-test-client-1",
            "client_secret": "conformance-test-secret-1"
        }
    }
)

# Run tests
results = api.run_plan(plan_id)

# Check results
assert results.passed, f"Tests failed: {results.failures}"
```

### GitHub Actions Example

```yaml
name: OIDC Conformance Tests

on: [push, pull_request]

jobs:
  conformance:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4

      - name: Start xavyo-idp
        run: |
          cargo build --release -p idp-api
          ./target/release/idp-api &
          sleep 10

      - name: Setup test clients
        run: psql -f tests/oidc-conformance/setup-test-clients.sql

      - name: Start conformance suite
        run: |
          cd tests/oidc-conformance
          docker-compose up -d
          sleep 30

      - name: Run conformance tests
        run: |
          python tests/oidc-conformance/run-tests.py \
            --plan oidcc-basic-certification-test-plan \
            --output results.json

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: conformance-results
          path: results.json
```

## Troubleshooting

### Connection Issues

If the conformance suite can't reach xavyo-idp:

1. Ensure xavyo-idp is running: `curl http://localhost:8080/.well-known/openid-configuration`
2. Check Docker network: `docker network inspect oidc-conformance_conformance`
3. Use `host.docker.internal` for host machine access

### SSL Certificate Errors

The conformance suite uses HTTPS. For local testing:
- Accept the self-signed certificate in your browser
- Or set `DISABLE_SSL_VERIFY=true` in docker-compose.yml

### Test Failures

Common issues:
- **invalid_client**: Check client credentials in database
- **redirect_uri_mismatch**: Add conformance suite callback URLs to client
- **unsupported_response_type**: Enable required response types in xavyo-idp

## Resources

- [OpenID Conformance Suite GitLab](https://gitlab.com/openid/conformance-suite)
- [OpenID Certification](https://openid.net/certification/)
- [Test Plan Documentation](https://openid.net/certification/connect_op_testing/)
- [API Documentation](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/API)

## Certification

After passing all tests, you can apply for official OpenID Certification:
1. Run tests on the [production conformance server](https://www.certification.openid.net/)
2. Submit results to OpenID Foundation
3. Pay certification fee
4. Receive certification mark

See: https://openid.net/certification/
