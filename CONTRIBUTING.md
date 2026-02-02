# Contributing to xavyo

Thanks for your interest in contributing to xavyo!

## Getting Started

### Prerequisites

- Rust 1.75+
- PostgreSQL 15+
- Docker & Docker Compose

### Development Setup

```bash
# Clone
git clone https://github.com/xavyo/xavyo.git
cd xavyo

# Generate JWT keys
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/test-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/test-private.pem -out keys/test-public.pem

# Start PostgreSQL
docker compose -f docker/docker-compose.yml up -d postgres

# Setup environment
cp .env.example .env

# Build and test
cargo build --workspace
cargo test --workspace
```

## How to Contribute

### 1. Find an Issue

- Browse [open issues](https://github.com/xavyo/xavyo/issues)
- Look for `good first issue` labels for easier tasks
- Comment on the issue to claim it

### 2. Create a Branch

```bash
git checkout -b feat/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 3. Write Code

Follow these standards:

```bash
# Format code
cargo fmt --all

# Check for lints
cargo clippy --workspace -- -D warnings

# Run tests
cargo test --workspace
```

### 4. Commit

Use [Conventional Commits](https://conventionalcommits.org):

```
feat: add user export endpoint
fix: resolve race condition in token refresh
docs: update API reference
refactor: simplify connector interface
test: add integration tests for SCIM
chore: update dependencies
```

### 5. Open a Pull Request

- Fill out the PR template
- Link related issues
- Ensure CI passes

## Code Guidelines

### Rust Style

- Follow `rustfmt` defaults
- No `clippy` warnings (treated as errors)
- Document public APIs with `///` comments
- Use `thiserror` for error types

### Multi-Tenancy

All database queries on tenant-scoped tables **must** include `tenant_id`:

```rust
// Correct
sqlx::query!("SELECT * FROM users WHERE tenant_id = $1 AND id = $2", tenant_id, user_id)

// Wrong - missing tenant filter
sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)
```

### Testing

- Write tests for new functionality
- Integration tests go in `tests/` directories
- Use `#[tokio::test]` for async tests

## Pull Request Checklist

- [ ] Code compiles (`cargo check --workspace`)
- [ ] Tests pass (`cargo test --workspace`)
- [ ] No clippy warnings (`cargo clippy --workspace -- -D warnings`)
- [ ] Code formatted (`cargo fmt --all --check`)
- [ ] Conventional commit messages
- [ ] Related issue linked

## Questions?

- Open a [Discussion](https://github.com/xavyo/xavyo/discussions)
- Check existing issues and docs first

## License

By contributing, you agree that your contributions will be licensed under the BSL 1.1 license.
