#!/usr/bin/env bash
# Wrapper for local cargo commands with SQLX_OFFLINE=true (see #99).
set -euo pipefail
export SQLX_OFFLINE=true
exec cargo "$@"
