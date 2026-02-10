# xavyo-cli

> Command-line interface for the xavyo identity platform.

## Purpose

The xavyo CLI enables developers and DevOps engineers to interact with the xavyo identity platform from the command line. It provides capabilities for authentication, tenant management, NHI lifecycle management, governance, configuration-as-code, and administration.

## Layer

app

## Status

🟡 **beta**

Functional CLI with 32 commands covering authentication, tenant management, NHI lifecycle, governance, connectors, and administration. Comprehensive test coverage (285 tests including 79 integration tests). Used internally for development and testing workflows.

## Dependencies

### Internal (xavyo)

None (standalone CLI that communicates via HTTP API)

### External (key)

- `clap` 4 - CLI framework with derive macros
- `tokio` - Async runtime
- `reqwest` - HTTP client with rustls-tls
- `serde` / `serde_json` / `serde_yaml` - Serialization
- `keyring` - Secure credential storage (system keychain)
- `dialoguer` - Interactive prompts
- `indicatif` - Progress bars
- `chrono` - Time handling
- `jsonwebtoken` - JWT decoding for token inspection

## Commands

| Command | Description |
|---------|-------------|
| `setup` | Interactive setup wizard for new users |
| `signup` | Create a new account in the system tenant |
| `login` | Authenticate with the xavyo platform |
| `logout` | Clear stored credentials and log out |
| `whoami` | Display current identity and tenant context |
| `init` | Provision a new tenant |
| `status` | Show tenant health and configuration |
| `agents` | Manage AI agents (list, create, get, update, delete, credentials) |
| `api-keys` | Manage tenant API keys (create, list, rotate, delete) |
| `credentials` | Manage NHI credentials (list, status, rotate, expire) |
| `tools` | Manage tools (list, create, get, delete) |
| `authorize` | Test agent-tool authorization |
| `doctor` | Diagnose connection and configuration issues |
| `apply` | Apply configuration from a YAML file |
| `export` | Export current configuration to YAML |
| `completions` | Generate shell completion scripts |
| `watch` | Watch a configuration file and auto-apply changes |
| `templates` | Pre-configured templates for quick setup |
| `tenant` | Show current tenant context |
| `upgrade` | Check for updates and upgrade the CLI |
| `users` | Manage users (admin) |
| `groups` | Manage groups (admin) |
| `sessions` | Manage active sessions |
| `service-accounts` | Manage service accounts (NHI) |
| `nhi` | Unified NHI management (lifecycle, credentials, permissions, risk, certifications, SoD) |
| `governance` | Governance: roles, entitlements, access requests |
| `connectors` | Manage connectors and provisioning |
| `webhooks` | Manage webhook subscriptions |
| `audit` | View audit logs |
| `policies` | Manage security policies (session, password, MFA, etc.) |
| `operations` | Provisioning operations and job tracking |
| `verify` | Check email verification status or resend verification email |

## Configuration

### Config File

**Location**: `~/.config/xavyo/config.yaml`

```yaml
api_url: https://api.xavyo.io
tenant_id: 550e8400-e29b-41d4-a716-446655440000
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `XAVYO_API_URL` | API endpoint URL | `https://api.xavyo.io` |
| `XAVYO_TOKEN` | Authentication token (for non-interactive use) | (none) |
| `XAVYO_TENANT_ID` | Override tenant context | (from config) |
| `XAVYO_CONFIG_DIR` | Config directory location | `~/.config/xavyo` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Authentication error |
| 4 | Network/API error |
| 5 | Validation error |
| 10 | Resource not found |
| 11 | Permission denied |

## Testing

```bash
# Run all tests (unit + integration)
cargo test -p xavyo-cli

# Run only integration tests
cargo test -p xavyo-cli --test '*'

# Run with output
cargo test -p xavyo-cli -- --nocapture
```

## Anti-Patterns

- Never store `XAVYO_TOKEN` in version control or logs
- Never run `xavyo apply` without `--dry-run` first in production
- Never share agent credentials between environments

## Related Crates

- `xavyo-api-auth` - Authentication endpoints consumed by CLI
- `xavyo-api-nhi` - NHI management API consumed by CLI
- `xavyo-api-governance` - Governance API consumed by CLI
- `xavyo-core` - Shared types (TenantId, UserId)
