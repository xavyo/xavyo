//! Guards shipped docs against claiming unshipped product paths as current
//! capability. Docs are read from the repo root (`CARGO_MANIFEST_DIR/../..`).

use std::path::PathBuf;

fn read_repo_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

const QUALIFIERS: &[&str] = &[
    "not a shipped",
    "not shipped",
    "not enabled",
    "not a working",
    "not issued",
    "not available",
    "optional",
    "feature-gated",
    "feature gated",
    "api-only",
    "api only",
    "crate/api",
    "no ui",
];

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i > s.len() {
        i = s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i > s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn occurrences(haystack: &str, needle: &str) -> Vec<usize> {
    let lower = haystack.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(rel) = lower[start..].find(&needle) {
        out.push(start + rel);
        start += rel + needle.len();
    }
    out
}

fn context_window(haystack: &str, idx: usize, needle_len: usize, radius: usize) -> &str {
    let from = floor_char_boundary(haystack, idx.saturating_sub(radius));
    let to = ceil_char_boundary(
        haystack,
        idx.saturating_add(needle_len).saturating_add(radius),
    );
    &haystack[from..to]
}

fn has_qualifier(ctx: &str) -> bool {
    let lower = ctx.to_ascii_lowercase();
    QUALIFIERS.iter().any(|q| lower.contains(q))
}

fn assert_each_occurrence_qualified(doc: &str, doc_name: &str, needle: &str) {
    let hits = occurrences(doc, needle);
    assert!(
        !hits.is_empty(),
        "{doc_name} should mention `{needle}` (qualified), but none found"
    );
    for idx in hits {
        let ctx = context_window(doc, idx, needle.len(), 180);
        assert!(
            has_qualifier(ctx),
            "{doc_name} mentions `{needle}` without a qualifier \
             (not / optional / feature-gated / API-only) nearby:\n{ctx}"
        );
    }
}

#[test]
fn readme_does_not_claim_aws_sts_as_delivered() {
    let readme = read_repo_file("README.md");
    assert!(
        !readme.contains("Short-lived AWS STS, Azure, GCP credentials via OAuth2 token exchange"),
        "README must not claim AWS STS / Azure / GCP dynamic credentials as a delivered feature"
    );
    assert_each_occurrence_qualified(&readme, "README.md", "AWS STS");
}

#[test]
fn readme_does_not_claim_agent_pki_issuance_as_delivered() {
    let readme = read_repo_file("README.md");
    assert!(
        !readme.contains("X.509 certificate issuance for agent mTLS authentication"),
        "README must not claim X.509 issuance for agent mTLS as a delivered feature"
    );
    assert_each_occurrence_qualified(&readme, "README.md", "agent mTLS");
}

#[test]
fn readme_cedar_mentions_are_feature_gated() {
    let readme = read_repo_file("README.md");
    assert_each_occurrence_qualified(&readme, "README.md", "Cedar");
}

#[test]
fn readme_entra_is_not_an_equal_builtin_ui_connector() {
    let readme = read_repo_file("README.md");
    assert!(
        !readme.contains("LDAP, Active Directory, REST APIs, Databases, Microsoft Entra ID"),
        "README must not list Entra ID as a built-in connector equally with LDAP"
    );

    let line = readme
        .lines()
        .find(|l| l.contains("Built-in Connectors"))
        .expect("README must have a Built-in Connectors row");
    let lower = line.to_ascii_lowercase();
    if lower.contains("entra") {
        assert!(
            has_qualifier(line),
            "Built-in Connectors lists Entra without an API-only qualifier:\n{line}"
        );
    }

    assert_each_occurrence_qualified(&readme, "README.md", "Entra");
}

#[test]
fn matrix_does_not_call_rest_or_database_stubs() {
    let matrix = read_repo_file("docs/crates/maturity-matrix.md");
    assert!(
        !matrix.contains("Stub implementation"),
        "maturity-matrix.md must not call xavyo-connector-rest a stub"
    );
    assert!(
        !matrix.contains("Skeleton only"),
        "maturity-matrix.md must not call xavyo-connector-database a skeleton"
    );
    assert!(
        !matrix.contains("xavyo-connector-rest | 🔴 alpha"),
        "maturity-matrix.md rest status must match CRATE.md, not an alpha stub"
    );
    assert!(
        !matrix.contains("xavyo-connector-database | 🔴 alpha"),
        "maturity-matrix.md database status must match CRATE.md, not an alpha skeleton"
    );
}

#[test]
fn index_rest_and_database_are_not_alpha_stubs() {
    let index = read_repo_file("docs/crates/index.md");
    assert!(
        !index.contains("Generic REST API connector | 🔴 alpha"),
        "index.md rest status must match CRATE.md, not alpha"
    );
    assert!(
        !index.contains("SQL database connector | 🔴 alpha"),
        "index.md database status must match CRATE.md, not alpha"
    );
    assert_each_occurrence_qualified(&index, "docs/crates/index.md", "Entra");
}
