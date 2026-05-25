# Rust Audit Report — xavyo-idp

Date: 2026-05-24 (refresh during deep-review verify-and-harden loop)
Previous: 2026-02-04

## Summary

| Metric | Before this pass | After |
|--------|------------------|-------|
| `cargo audit` vulnerabilities | **18** | **4** |
| of which Critical (9.x) | 1 (`lettre`) | 0 |
| of which High (7.x–8.7) | 8 | 0 |
| Unmaintained warnings | 4 | 4 |
| `cargo fmt --check` | clean | clean |

`cargo-audit` reinstalled (`cargo install cargo-audit`). All Critical and High
advisories were resolved by in-range / minor dependency bumps. The 4 remaining
are either no-fix-available (accepted) or only reachable under opt-in AWS
feature flags against trusted AWS endpoints.

---

## Fixed (all Critical + High)

| Crate | Advisory | Sev | Fix applied |
|-------|----------|-----|-------------|
| `lettre` | RUSTSEC-2026-0141 (TLS hostname verification disabled on Boring backend) | **9.1 CRIT** | `cargo update` 0.11.19 → 0.11.22 |
| `aws-lc-sys` | RUSTSEC-2026-0046, -0047 (PKCS7_verify chain/sig bypass) | **7.5 HIGH** | bumped `aws-lc-rs` 1.15.4 → 1.17.0 ⇒ `aws-lc-sys` 0.37 → 0.41 |
| `aws-lc-sys` | RUSTSEC-2026-0048 (CRL distribution-point scope logic) | **7.4 HIGH** | same |
| `aws-lc-sys` | RUSTSEC-2026-0044 (X.509 name-constraint bypass) | med | same |
| `aws-lc-sys` | RUSTSEC-2026-0045 (AES-CCM timing side-channel) | 5.9 med | same |
| `quinn-proto` | RUSTSEC-2026-0037 (endpoint DoS) | **8.7 HIGH** | `cargo update` 0.11.13 → 0.11.14 |
| `thin-vec` | RUSTSEC-2026-0103 (UAF/double-free in IntoIter::drop) | **7.3 HIGH** | `cargo update` 0.2.14 → 0.2.18 |
| `rustls-webpki` (0.103.x copy) | RUSTSEC-2026-0049/0098/0099/0104 | med | `cargo update` 0.103.9 → 0.103.13 |
| `tar` | RUSTSEC-2026-0068 + symlink chmod | 5.1 med | `cargo update` 0.4.44 → 0.4.46 |

---

## Remaining (4) — accepted / documented

### 1. `rsa` 0.9.x — RUSTSEC-2023-0071 (Marvin Attack, 5.9 medium) — NO FIX AVAILABLE
Carried over from the 2026-02-04 report. No upstream fix exists. Risk is
timing-based key recovery via PKCS#1 v1.5 decryption. xavyo does not perform
PKCS#1 v1.5 *decryption* — `rsa` arrives transitively via `sqlx-mysql` (unused —
we build sqlx with postgres only) and RSA *signing/verification* for JWTs uses
`jsonwebtoken`/`aws-lc`/`ring`, not the `rsa` crate's vulnerable decrypt path.
**Action:** monitor https://rustsec.org/advisories/RUSTSEC-2023-0071; accept.

### 2–4. `rustls-webpki` 0.101.7 — RUSTSEC-2026-0098/0099/0104 (cert-validation edge cases)
**Only present under the opt-in `aws-ses` / `aws-provider` feature flags.** The
0.101.7 copy is pulled exclusively by the AWS SDK TLS stack:
`aws-sdk-{sts,sesv2,secretsmanager}` → `aws-smithy-http-client` → `hyper-rustls 0.24`
→ `rustls 0.21` → `rustls-webpki 0.101.7`. Those AWS crates are **optional**
dependencies (`crates/xavyo-api-auth` `aws-ses`, `crates/xavyo-secrets`
`aws-provider`) and are **not enabled in the default build**, which uses lettre
(SMTP) for email and env/file providers for secrets. When the AWS features *are*
enabled, the affected code path is TLS validation against AWS's own pinned-CA
endpoints (STS / SES / Secrets Manager), where the CRL-parse-panic and
name-constraint-acceptance advisories have low practical exploitability. The fix
requires the upstream AWS SDK to move to `rustls 0.23`; not actionable from this
repo without forking the SDK.
**Action:** accept while AWS features are off by default; track AWS SDK rustls
upgrade; if AWS features ship enabled, pin `hyper-rustls`/`rustls` overrides.

---

## Unmaintained warnings (4) — non-exploitable

| Crate | Advisory | Source | Note |
|-------|----------|--------|------|
| `proc-macro-error` | RUSTSEC-2024-0370 | `utoipa-gen` (build-time) | macro expansion only; no runtime surface |
| `number_prefix` | RUSTSEC-2025-0119 | `indicatif` (CLI progress bars) | CLI cosmetic; not in server path |
| `rand` | RUSTSEC-2026-0097 | transitive | unsound *only* with a custom logger that calls `rand::rng()` during logging — not xavyo's usage |
| `atty`/legacy | (carried) | transitive | superseded; tracked |

---

## Commands

```bash
cargo install cargo-audit          # one-time
cargo audit                        # 4 documented advisories remain (see above)
cargo update -p <crate>            # how the fixes above were applied (Lock-only)
```

## Verification

After the dependency bumps, `cargo check` on `idp-api` + core auth/oauth crates
was re-run to confirm the workspace still compiles (the `aws-lc-sys` 0.41 bump
rebuilds the bundled AWS-LC C library). `cargo fmt --check` remains clean.
