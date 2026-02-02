# Docker JWT Keys

This directory should contain RSA keys for JWT signing in Docker environment.

## Generate Keys

```bash
# Generate private key
openssl genpkey -algorithm RSA -out jwt_private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in jwt_private.pem -out jwt_public.pem
```

## Required Files

- `jwt_private.pem` - RSA private key (for signing)
- `jwt_public.pem` - RSA public key (for verification)

These files are gitignored for security.
