# JWT Keys

This directory should contain RSA keys for JWT signing.

## Generate Keys

```bash
# Generate private key
openssl genpkey -algorithm RSA -out test-private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in test-private.pem -out test-public.pem
```

## Required Files

- `test-private.pem` - RSA private key (for signing)
- `test-public.pem` - RSA public key (for verification)

These files are gitignored for security.
