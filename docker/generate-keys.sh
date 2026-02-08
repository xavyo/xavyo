#!/bin/bash
set -e

KEYS_DIR="$(cd "$(dirname "$0")/keys" 2>/dev/null && pwd)" || {
    KEYS_DIR="$(dirname "$0")/keys"
    mkdir -p "$KEYS_DIR"
    KEYS_DIR="$(cd "$KEYS_DIR" && pwd)"
}

if [ ! -f "$KEYS_DIR/jwt_private.pem" ]; then
    openssl genpkey -algorithm RSA -out "$KEYS_DIR/jwt_private.pem" -pkeyopt rsa_keygen_bits:2048
    openssl rsa -pubout -in "$KEYS_DIR/jwt_private.pem" -out "$KEYS_DIR/jwt_public.pem"
    chmod 600 "$KEYS_DIR/jwt_private.pem"
    chmod 644 "$KEYS_DIR/jwt_public.pem"
    echo "JWT keys generated in $KEYS_DIR"
else
    echo "JWT keys already exist in $KEYS_DIR, skipping."
fi
