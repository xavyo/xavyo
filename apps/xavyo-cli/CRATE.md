# xavyo-cli

> Command-line interface for the xavyo identity platform.

## Purpose

The xavyo CLI enables developers and DevOps engineers to interact with the xavyo identity platform from the command line. It provides capabilities for:

- **Authentication**: Device code OAuth flow, credential management
- **Tenant Management**: Provisioning, health checks, configuration
- **AI Agent Management**: Register, configure, and manage AI agents with OWASP ASI compliance
- **Tool Authorization**: Define and manage tool permissions for agents
- **Configuration as Code**: Apply and export YAML configurations with GitOps support

## Layer

app

## Status

🟡 **beta**

Functional CLI with 17 commands. Comprehensive test coverage (285 tests including 79 integration tests). Used internally for development and testing workflows.

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

## Installation

```bash
# Build from source
cargo build --release -p xavyo-cli

# Install to cargo bin directory
cargo install --path apps/xavyo-cli

# Verify installation
xavyo --version
```

## Quick Start

```bash
# 1. Run interactive setup wizard
xavyo setup

# 2. Authenticate with the platform
xavyo login

# 3. Check your identity and tenant context
xavyo whoami

# 4. List AI agents in your tenant
xavyo agents list

# 5. List available tools
xavyo tools list
```

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
| `agents` | Manage AI agents (list, create, get, delete, credentials) - supports `--interactive` |
| `api-keys` | Manage tenant API keys (create, list, rotate, delete) - supports `--interactive` |
| `credentials` | Manage NHI credentials (list, status, rotate, expire) - supports `--interactive` |
| `tools` | Manage tools (list, create, get, delete) |
| `authorize` | Test agent-tool authorization |
| `doctor` | Diagnose connection and configuration issues |
| `apply` | Apply configuration from a YAML file |
| `export` | Export current configuration to YAML |
| `completions` | Generate shell completion scripts |
| `watch` | Watch a configuration file and auto-apply changes |
| `templates` | Pre-configured templates for quick setup |
| `upgrade` | Check for updates and upgrade the CLI |

## Command Reference

### setup

Interactive setup wizard for new users.

**Usage**: `xavyo setup`

**Example**:
```bash
xavyo setup
# Follow prompts to configure API URL and authenticate
```

### signup

Create a new account in the system tenant.

**Usage**: `xavyo signup [OPTIONS]`

**Flags**:
- `--email <EMAIL>` - Email address for the account
- `--name <NAME>` - Display name

**Example**:
```bash
xavyo signup --email user@example.com --name "John Doe"
```

### login

Authenticate with the xavyo platform using device code flow.

**Usage**: `xavyo login [OPTIONS]`

**Flags**:
- `--no-browser` - Don't open browser automatically
- `--json` - Output as JSON

**Example**:
```bash
xavyo login
# Opens browser for authentication
# Polls for completion automatically
```

### logout

Clear stored credentials and log out.

**Usage**: `xavyo logout`

**Example**:
```bash
xavyo logout
# Credentials cleared from keyring
```

### whoami

Display current identity and tenant context.

**Usage**: `xavyo whoami [OPTIONS]`

**Flags**:
- `--json` - Output as JSON

**Example**:
```bash
xavyo whoami
# Shows: user email, user ID, tenant ID, tenant name
```

### init

Provision a new tenant.

**Usage**: `xavyo init [OPTIONS] <NAME>`

**Arguments**:
- `<NAME>` - Tenant name

**Flags**:
- `--slug <SLUG>` - URL-friendly identifier
- `--json` - Output as JSON

**Example**:
```bash
xavyo init "My Company" --slug my-company
```

### status

Show tenant health and configuration.

**Usage**: `xavyo status [OPTIONS]`

**Flags**:
- `--json` - Output as JSON

**Example**:
```bash
xavyo status
# Shows: tenant info, agent count, tool count, health status
```

### agents

Manage AI agents in the current tenant.

**Usage**: `xavyo agents <SUBCOMMAND>`

**Subcommands**:
- `list` - List all agents (with filtering and pagination)
- `create` - Create a new agent
- `get` - Get agent details
- `update` - Update an existing agent (F-051)
- `delete` - Delete an agent
- `credentials` - Manage agent credentials

**List Flags** (F-051):
- `--type, -t <TYPE>` - Filter by agent type: copilot, autonomous, workflow, orchestrator
- `--status, -s <STATUS>` - Filter by status: active, inactive, pending
- `--page <N>` - Page number (1-based, overrides --offset)
- `--per-page <N>` - Agents per page (max: 100, overrides --limit)
- `--limit <N>` - Maximum agents to return (default: 50)
- `--offset <N>` - Offset for pagination (default: 0)
- `--json` - Output as JSON

**Update Flags** (F-051):
- `--name, -n <NAME>` - New agent name
- `--description, -d <DESC>` - New agent description
- `--status, -s <STATUS>` - New agent status: active, inactive, pending
- `--json` - Output as JSON

**Examples**:
```bash
# List all agents
xavyo agents list --json

# List with filtering (F-051)
xavyo agents list --type copilot
xavyo agents list --status active
xavyo agents list --type autonomous --status inactive

# List with pagination (F-051)
xavyo agents list --per-page 10 --page 2
xavyo agents list --per-page 25 --page 1 --type copilot

# Create a new agent
xavyo agents create my-agent \
  --type autonomous \
  --model-provider anthropic \
  --model-name claude-sonnet-4 \
  --risk-level medium \
  --description "Code review assistant"

# Get agent details
xavyo agents get <agent-id>

# Update an agent (F-051)
xavyo agents update <agent-id> --name new-name
xavyo agents update <agent-id> --status inactive
xavyo agents update <agent-id> --description "Updated description"
xavyo agents update <agent-id> --name new-bot --status active --json

# Delete an agent (with confirmation prompt)
xavyo agents delete <agent-id>

# Delete without confirmation (for scripts)
xavyo agents delete <agent-id> --yes

# Rotate agent credentials
xavyo agents credentials rotate <agent-id>

# Interactive mode for guided agent creation (F-053)
xavyo agents create --interactive
```

**Interactive Mode** (F-053): Use `--interactive` or `-i` flag for guided prompts:
- Prompts for agent name with validation
- Select agent type from list with descriptions
- Select risk level from list with descriptions
- Optional description input

### api-keys

Manage tenant API keys for programmatic access.

**Usage**: `xavyo api-keys <SUBCOMMAND>`

**Subcommands**:
- `create` - Create a new API key
- `list` - List all API keys
- `rotate` - Rotate an existing API key
- `delete` - Delete an API key

**Examples**:
```bash
# Create a basic API key
xavyo api-keys create "my-dev-key"

# Create an API key with scopes and expiration
xavyo api-keys create "ci-pipeline" \
  --scopes nhi:agents:*,audit:* \
  --expires-in 30

# List all API keys
xavyo api-keys list --json

# Rotate an API key
xavyo api-keys rotate <key-id>

# Rotate with immediate deactivation of old key
xavyo api-keys rotate <key-id> --deactivate-old --yes

# Delete an API key (with confirmation prompt)
xavyo api-keys delete <key-id>

# Delete without confirmation (for scripts)
xavyo api-keys delete <key-id> --yes

# Interactive mode for guided API key creation (F-053)
xavyo api-keys create --interactive
```

**Interactive Mode** (F-053): Use `--interactive` or `-i` flag for guided prompts:
- Prompts for API key name
- Multi-select checkbox for scope selection with descriptions
- Warning when no scopes selected (full access)
- Optional expiration days input

**Important**: API keys are shown only once when created or rotated. Store them securely immediately - they cannot be retrieved later.

### credentials

Manage NHI credentials directly (alternative to `agents credentials`).

**Usage**: `xavyo credentials <SUBCOMMAND>`

**Subcommands**:
- `list` - List credentials for an agent
- `status` - View detailed status of a credential
- `rotate` - Rotate a credential (generates new secret)
- `expire` - Set credential expiration date

**Examples**:
```bash
# List credentials for an agent
xavyo credentials list <agent-id>

# List only active credentials
xavyo credentials list <agent-id> --active-only

# View detailed status of a credential
xavyo credentials status <credential-id> -a <agent-id>

# Rotate a credential
xavyo credentials rotate <credential-id> -a <agent-id>

# Rotate with grace period (old credential valid for 24 hours)
xavyo credentials rotate <credential-id> -a <agent-id> --grace-period-hours 24

# Set credential expiration
xavyo credentials expire <credential-id> -a <agent-id> --at "2026-03-01T00:00:00Z"

# JSON output for scripting
xavyo credentials list <agent-id> --json

# Interactive mode for guided credential rotation (F-053)
xavyo credentials rotate --interactive -a <agent-id>
```

**Interactive Mode** (F-053): Use `--interactive` or `-i` flag for guided prompts:
- Select credential type from list with descriptions
- Select grace period from predefined options with descriptions
- Confirmation prompt before rotation

**Important**: Credential secrets are shown only once when rotated. Store them securely immediately - they cannot be retrieved later.

**Expiring Soon Warning**: Credentials expiring within 7 days display a warning in the status output.

### tools

Manage tools in the current tenant.

**Usage**: `xavyo tools <SUBCOMMAND>`

**Subcommands**:
- `list` - List all tools
- `create` - Create a new tool
- `get` - Get tool details
- `delete` - Delete a tool

**Examples**:
```bash
# List all tools
xavyo tools list --json

# Create a new tool
xavyo tools create send-email \
  --risk-level medium \
  --category communication \
  --description "Send email via SMTP" \
  --schema '{"type":"object","properties":{"to":{"type":"string"}}}'

# Get tool details
xavyo tools get <tool-id>

# Delete a tool
xavyo tools delete <tool-id> --force
```

### authorize

Test agent-tool authorization.

**Usage**: `xavyo authorize <AGENT_ID> <TOOL_ID> [OPTIONS]`

**Arguments**:
- `<AGENT_ID>` - Agent UUID
- `<TOOL_ID>` - Tool UUID

**Flags**:
- `--params <JSON>` - Tool parameters as JSON
- `--json` - Output as JSON

**Example**:
```bash
xavyo authorize <agent-id> <tool-id> --params '{"to":"user@example.com"}'
# Returns: allowed/denied with reason
```

### doctor

Diagnose connection and configuration issues.

**Usage**: `xavyo doctor [OPTIONS]`

**Flags**:
- `--json` - Output as JSON

**Example**:
```bash
xavyo doctor
# Checks: API connectivity, auth status, config validity
```

### apply

Apply configuration from a YAML file.

**Usage**: `xavyo apply <FILE> [OPTIONS]`

**Arguments**:
- `<FILE>` - Path to YAML configuration file

**Flags**:
- `--dry-run` - Show what would change without applying
- `--json` - Output as JSON

**Example**:
```bash
# Apply configuration
xavyo apply config.yaml

# Preview changes
xavyo apply config.yaml --dry-run
```

### export

Export current configuration to YAML.

**Usage**: `xavyo export [OPTIONS]`

**Flags**:
- `--output <FILE>` - Output file path (default: stdout)
- `--format <FORMAT>` - Output format: yaml, json

**Example**:
```bash
# Export to file
xavyo export --output backup.yaml

# Export to stdout
xavyo export
```

### completions

Generate shell completion scripts.

**Usage**: `xavyo completions <SHELL>`

**Arguments**:
- `<SHELL>` - Shell type: bash, zsh, fish, powershell

**Example**:
```bash
# Generate bash completions
xavyo completions bash > ~/.bash_completion.d/xavyo

# Generate zsh completions
xavyo completions zsh > ~/.zfunc/_xavyo
```

### watch

Watch a configuration file and auto-apply changes.

**Usage**: `xavyo watch <FILE> [OPTIONS]`

**Arguments**:
- `<FILE>` - Path to YAML configuration file

**Flags**:
- `--interval <SECONDS>` - Poll interval (default: 5)

**Example**:
```bash
xavyo watch config.yaml
# Monitors file for changes, applies automatically
# Press Ctrl+C to stop
```

### templates

Pre-configured templates for quick setup.

**Usage**: `xavyo templates <SUBCOMMAND>`

**Subcommands**:
- `list` - List available templates
- `apply` - Apply a template

**Example**:
```bash
# List templates
xavyo templates list

# Apply a template
xavyo templates apply code-review-agent
```

### upgrade

Check for updates and upgrade the CLI.

**Usage**: `xavyo upgrade [OPTIONS]`

**Flags**:
- `--check` - Check for updates without installing
- `--force` - Skip confirmation prompt

**Example**:
```bash
# Check for updates
xavyo upgrade --check

# Upgrade to latest version
xavyo upgrade
```

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

### Credential Storage

Credentials are stored securely using the system keychain:
- **macOS**: Keychain Access
- **Linux**: Secret Service (GNOME Keyring, KWallet)
- **Windows**: Windows Credential Manager

Fallback: Encrypted file at `~/.config/xavyo/credentials` (AES-GCM encryption)

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

### Running Tests

```bash
# Run all tests (unit + integration)
cargo test -p xavyo-cli

# Run only integration tests
cargo test -p xavyo-cli --test '*'

# Run specific integration test file
cargo test -p xavyo-cli --test auth_tests
cargo test -p xavyo-cli --test agent_tests
cargo test -p xavyo-cli --test tool_tests
cargo test -p xavyo-cli --test config_tests
cargo test -p xavyo-cli --test error_tests

# Run with output
cargo test -p xavyo-cli -- --nocapture
```

### Test Coverage

| Test Category | Count | Description |
|---------------|-------|-------------|
| Unit tests | 206 | Tests for individual modules |
| Integration tests | 79 | End-to-end API mock tests |
| **Total** | **285** | |

### Integration Test Structure

```text
apps/xavyo-cli/tests/
├── common/
│   └── mod.rs          # TestContext, mock helpers, fixtures
├── auth_tests.rs       # Authentication flow tests (login, whoami, logout)
├── agent_tests.rs      # Agent CRUD operations
├── tool_tests.rs       # Tool CRUD operations
├── config_tests.rs     # Apply/export configuration
└── error_tests.rs      # Error handling (401, 404, 500, timeout)
```

## CI/CD Integration

### Non-Interactive Authentication

```bash
# Set token from environment variable
export XAVYO_TOKEN="your-api-token"
export XAVYO_API_URL="https://api.xavyo.io"

# Run commands non-interactively
xavyo agents list --json
```

### Example GitHub Actions Workflow

```yaml
name: Sync Agents
on:
  push:
    paths:
      - 'agents/*.yaml'

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install xavyo CLI
        run: cargo install --path apps/xavyo-cli

      - name: Apply Configuration
        env:
          XAVYO_TOKEN: ${{ secrets.XAVYO_TOKEN }}
          XAVYO_API_URL: ${{ secrets.XAVYO_API_URL }}
        run: xavyo apply agents/config.yaml --json
```

### Exit Code Handling

```bash
#!/bin/bash
set -e

xavyo apply config.yaml
if [ $? -eq 0 ]; then
  echo "Configuration applied successfully"
elif [ $? -eq 3 ]; then
  echo "Authentication failed - check XAVYO_TOKEN"
  exit 1
elif [ $? -eq 10 ]; then
  echo "Resource not found - check config"
  exit 1
fi
```

## Troubleshooting

### Authentication Failures

**Symptom**: `Error: Authentication failed` or `401 Unauthorized`

**Solutions**:
1. Run `xavyo logout` then `xavyo login` to refresh credentials
2. Check if token has expired (tokens valid for 24 hours by default)
3. Verify API URL is correct: `xavyo doctor`
4. For CI/CD, ensure `XAVYO_TOKEN` is set correctly

### Network/Connectivity Issues

**Symptom**: `Error: Connection refused` or timeout errors

**Solutions**:
1. Run `xavyo doctor` to diagnose connectivity
2. Check if API URL is reachable: `curl -I https://api.xavyo.io/health`
3. Verify proxy settings if behind corporate firewall
4. Check DNS resolution

### Keyring Access Problems

**Symptom**: `Error: Failed to access keyring` on Linux

**Solutions**:
1. Ensure a secret service is running (GNOME Keyring or KWallet)
2. Start the service: `eval $(gnome-keyring-daemon --start)`
3. Fall back to file storage: set `XAVYO_CREDENTIAL_STORE=file`

### Configuration Errors

**Symptom**: `Error: Invalid configuration`

**Solutions**:
1. Validate YAML syntax: `yq . config.yaml`
2. Check required fields are present
3. Run `xavyo apply config.yaml --dry-run` to preview

### Version Mismatch

**Symptom**: `Error: API version mismatch`

**Solutions**:
1. Run `xavyo upgrade` to update CLI
2. Check API version compatibility in release notes
3. Downgrade if needed: `cargo install xavyo-cli@0.1.0`

## Anti-Patterns

- Never store `XAVYO_TOKEN` in version control or logs
- Never run `xavyo apply` without `--dry-run` first in production
- Never share agent credentials between environments
- Never use `--force` flags in automated pipelines without review

## Related Crates

- `xavyo-api-agents` - Server-side agent management API
- `xavyo-api-auth` - Authentication endpoints consumed by CLI
- `xavyo-core` - Shared types (TenantId, UserId)
