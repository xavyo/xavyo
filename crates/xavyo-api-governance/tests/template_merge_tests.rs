//! Tests for template merge resolution logic (F058 - TemplateMergeService).
//!
//! Tests the stateless merge resolution methods that resolve conflicts
//! between values from multiple sources using different strategies.

use chrono::{Duration, Utc};
use serde_json::json;
use xavyo_api_governance::services::{MergeValue, TemplateMergeService};
use xavyo_db::models::{TemplateMergeStrategy, TemplateNullHandling};

// =============================================================================
// Helper
// =============================================================================

fn make_value(
    source: &str,
    value: serde_json::Value,
    timestamp: Option<chrono::DateTime<chrono::Utc>>,
) -> MergeValue {
    MergeValue {
        source: source.to_string(),
        value,
        timestamp,
    }
}

// =============================================================================
// Source Precedence Strategy Tests
// =============================================================================

/// Three sources (hr, ad, manual) with values. HR is first in precedence.
/// Assert HR value wins.
#[test]
fn test_source_precedence_basic() {
    let values = vec![
        make_value("hr", json!("John"), None),
        make_value("ad", json!("Jonathan"), None),
        make_value("manual", json!("Johnny"), None),
    ];
    let precedence = vec!["hr".to_string(), "ad".to_string(), "manual".to_string()];

    let result = TemplateMergeService::resolve_source_precedence(
        &values,
        &precedence,
        TemplateNullHandling::Merge,
    )
    .expect("should resolve successfully");

    assert_eq!(result.value, json!("John"));
    assert_eq!(result.resolved_from, vec!["hr"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::SourcePrecedence);
}

/// HR source has null value, AD has "Jane". With Merge null handling,
/// assert AD wins (skips null HR).
#[test]
fn test_source_precedence_skip_null_merge() {
    let values = vec![
        make_value("hr", json!(null), None),
        make_value("ad", json!("Jane"), None),
        make_value("manual", json!("Janet"), None),
    ];
    let precedence = vec!["hr".to_string(), "ad".to_string(), "manual".to_string()];

    let result = TemplateMergeService::resolve_source_precedence(
        &values,
        &precedence,
        TemplateNullHandling::Merge,
    )
    .expect("should resolve successfully");

    assert_eq!(result.value, json!("Jane"));
    assert_eq!(result.resolved_from, vec!["ad"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::SourcePrecedence);
}

/// HR source has null value. With PreserveEmpty null handling,
/// assert null from HR is returned.
#[test]
fn test_source_precedence_preserve_null() {
    let values = vec![
        make_value("hr", json!(null), None),
        make_value("ad", json!("Jane"), None),
    ];
    let precedence = vec!["hr".to_string(), "ad".to_string()];

    let result = TemplateMergeService::resolve_source_precedence(
        &values,
        &precedence,
        TemplateNullHandling::PreserveEmpty,
    )
    .expect("should resolve successfully");

    assert!(result.value.is_null());
    assert_eq!(result.resolved_from, vec!["hr"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::SourcePrecedence);
}

/// Precedence list has ["hr", "ad"] but only "manual" source has a value.
/// Assert manual value is used as fallback.
#[test]
fn test_source_precedence_fallback_to_unlisted() {
    let values = vec![make_value("manual", json!("FallbackName"), None)];
    let precedence = vec!["hr".to_string(), "ad".to_string()];

    let result = TemplateMergeService::resolve_source_precedence(
        &values,
        &precedence,
        TemplateNullHandling::Merge,
    )
    .expect("should resolve with fallback");

    assert_eq!(result.value, json!("FallbackName"));
    assert_eq!(result.resolved_from, vec!["manual"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::SourcePrecedence);
}

/// Empty values slice. Assert error.
#[test]
fn test_source_precedence_empty_values_error() {
    let values: Vec<MergeValue> = vec![];
    let precedence = vec!["hr".to_string()];

    let err = TemplateMergeService::resolve_source_precedence(
        &values,
        &precedence,
        TemplateNullHandling::Merge,
    )
    .expect_err("should fail with empty values");

    assert_eq!(err.strategy, TemplateMergeStrategy::SourcePrecedence);
    assert!(err.message.contains("No values"));
}

// =============================================================================
// Timestamp Wins Strategy Tests
// =============================================================================

/// Three sources with different timestamps. Assert newest timestamp wins.
#[test]
fn test_timestamp_wins_basic() {
    let now = Utc::now();
    let values = vec![
        make_value("hr", json!("Old"), Some(now - Duration::hours(2))),
        make_value("ad", json!("Newest"), Some(now)),
        make_value("manual", json!("Middle"), Some(now - Duration::hours(1))),
    ];

    let result = TemplateMergeService::resolve_timestamp_wins(&values, TemplateNullHandling::Merge)
        .expect("should resolve successfully");

    assert_eq!(result.value, json!("Newest"));
    assert_eq!(result.resolved_from, vec!["ad"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::TimestampWins);
}

/// Two sources with identical timestamps. Assert first one in order wins.
#[test]
fn test_timestamp_wins_tie_first_wins() {
    let now = Utc::now();
    let values = vec![
        make_value("hr", json!("First"), Some(now)),
        make_value("ad", json!("Second"), Some(now)),
    ];

    let result = TemplateMergeService::resolve_timestamp_wins(&values, TemplateNullHandling::Merge)
        .expect("should resolve successfully");

    assert_eq!(result.value, json!("First"));
    assert_eq!(result.resolved_from, vec!["hr"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::TimestampWins);
}

/// One source with timestamp, one without. Assert timestamped source wins.
#[test]
fn test_timestamp_wins_no_timestamp_loses() {
    let now = Utc::now();
    let values = vec![
        make_value("hr", json!("NoTimestamp"), None),
        make_value("ad", json!("HasTimestamp"), Some(now)),
    ];

    let result = TemplateMergeService::resolve_timestamp_wins(&values, TemplateNullHandling::Merge)
        .expect("should resolve successfully");

    assert_eq!(result.value, json!("HasTimestamp"));
    assert_eq!(result.resolved_from, vec!["ad"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::TimestampWins);
}

/// Source with newest timestamp has null value. With Merge,
/// assert next non-null value by timestamp wins.
#[test]
fn test_timestamp_wins_null_handling_merge() {
    let now = Utc::now();
    let values = vec![
        make_value("hr", json!("OlderValid"), Some(now - Duration::hours(1))),
        make_value("ad", json!(null), Some(now)),
    ];

    let result = TemplateMergeService::resolve_timestamp_wins(&values, TemplateNullHandling::Merge)
        .expect("should resolve successfully");

    // The null value from ad is filtered out by Merge handling,
    // so the older non-null value from hr wins.
    assert_eq!(result.value, json!("OlderValid"));
    assert_eq!(result.resolved_from, vec!["hr"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::TimestampWins);
}

// =============================================================================
// Concatenate Unique Strategy Tests
// =============================================================================

/// Three sources with values "a", "b", "a". Assert result is array ["a", "b"] (unique).
#[test]
fn test_concatenate_unique_basic() {
    let values = vec![
        make_value("src1", json!("a"), None),
        make_value("src2", json!("b"), None),
        make_value("src3", json!("a"), None),
    ];

    let result =
        TemplateMergeService::resolve_concatenate_unique(&values, TemplateNullHandling::Merge)
            .expect("should resolve successfully");

    assert_eq!(result.value, json!(["a", "b"]));
    assert_eq!(result.strategy, TemplateMergeStrategy::ConcatenateUnique);
    // src1 and src2 contributed unique values; src3 was a duplicate of src1
    assert!(result.resolved_from.contains(&"src1".to_string()));
    assert!(result.resolved_from.contains(&"src2".to_string()));
}

/// Sources with "a", null, "b". With Merge, assert result is ["a", "b"].
#[test]
fn test_concatenate_unique_skips_null_merge() {
    let values = vec![
        make_value("src1", json!("a"), None),
        make_value("src2", json!(null), None),
        make_value("src3", json!("b"), None),
    ];

    let result =
        TemplateMergeService::resolve_concatenate_unique(&values, TemplateNullHandling::Merge)
            .expect("should resolve successfully");

    assert_eq!(result.value, json!(["a", "b"]));
    assert_eq!(result.strategy, TemplateMergeStrategy::ConcatenateUnique);
}

/// Sources with "a", null, "b". With PreserveEmpty, assert result is ["a", null, "b"].
#[test]
fn test_concatenate_unique_preserves_null() {
    let values = vec![
        make_value("src1", json!("a"), None),
        make_value("src2", json!(null), None),
        make_value("src3", json!("b"), None),
    ];

    let result = TemplateMergeService::resolve_concatenate_unique(
        &values,
        TemplateNullHandling::PreserveEmpty,
    )
    .expect("should resolve successfully");

    assert_eq!(result.value, json!(["a", null, "b"]));
    assert_eq!(result.strategy, TemplateMergeStrategy::ConcatenateUnique);
}

// =============================================================================
// First Wins Strategy Tests
// =============================================================================

/// Three sources. Assert first non-null value wins.
#[test]
fn test_first_wins_basic() {
    let values = vec![
        make_value("hr", json!("Alice"), None),
        make_value("ad", json!("Bob"), None),
        make_value("manual", json!("Charlie"), None),
    ];

    let result = TemplateMergeService::resolve_first_wins(&values, TemplateNullHandling::Merge)
        .expect("should resolve successfully");

    assert_eq!(result.value, json!("Alice"));
    assert_eq!(result.resolved_from, vec!["hr"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::FirstWins);
}

/// First source is null, second has value. With Merge, assert second wins.
#[test]
fn test_first_wins_skip_null() {
    let values = vec![
        make_value("hr", json!(null), None),
        make_value("ad", json!("Bob"), None),
        make_value("manual", json!("Charlie"), None),
    ];

    let result = TemplateMergeService::resolve_first_wins(&values, TemplateNullHandling::Merge)
        .expect("should resolve successfully");

    assert_eq!(result.value, json!("Bob"));
    assert_eq!(result.resolved_from, vec!["ad"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::FirstWins);
}

// =============================================================================
// Manual Only Strategy Tests
// =============================================================================

/// Sources "hr"="John", "manual"="Jane". Assert "Jane" from manual wins.
#[test]
fn test_manual_only_accepts_manual_source() {
    let values = vec![
        make_value("hr", json!("John"), None),
        make_value("manual", json!("Jane"), None),
    ];

    let result = TemplateMergeService::resolve_manual_only(&values, TemplateNullHandling::Merge)
        .expect("should resolve successfully");

    assert_eq!(result.value, json!("Jane"));
    assert_eq!(result.resolved_from, vec!["manual"]);
    assert_eq!(result.strategy, TemplateMergeStrategy::ManualOnly);
}

/// Only "hr" source present. Assert error.
#[test]
fn test_manual_only_rejects_non_manual() {
    let values = vec![make_value("hr", json!("John"), None)];

    let err = TemplateMergeService::resolve_manual_only(&values, TemplateNullHandling::Merge)
        .expect_err("should fail without manual source");

    assert_eq!(err.strategy, TemplateMergeStrategy::ManualOnly);
    assert!(err.message.contains("manual"));
}

// =============================================================================
// Dispatch Tests
// =============================================================================

/// Call `TemplateMergeService::resolve()` with each strategy and verify
/// it dispatches to the correct method.
#[test]
fn test_resolve_dispatches_correctly() {
    let now = Utc::now();
    let values = vec![
        make_value("hr", json!("HR"), Some(now - Duration::hours(1))),
        make_value("ad", json!("AD"), Some(now)),
        make_value("manual", json!("Manual"), Some(now - Duration::hours(2))),
    ];
    let precedence = vec!["hr".to_string(), "ad".to_string(), "manual".to_string()];

    // SourcePrecedence -- HR should win (first in precedence)
    let result = TemplateMergeService::resolve(
        TemplateMergeStrategy::SourcePrecedence,
        &values,
        Some(&precedence),
        TemplateNullHandling::Merge,
    )
    .expect("source_precedence dispatch should work");
    assert_eq!(result.strategy, TemplateMergeStrategy::SourcePrecedence);
    assert_eq!(result.value, json!("HR"));

    // TimestampWins -- AD should win (newest timestamp)
    let result = TemplateMergeService::resolve(
        TemplateMergeStrategy::TimestampWins,
        &values,
        None,
        TemplateNullHandling::Merge,
    )
    .expect("timestamp_wins dispatch should work");
    assert_eq!(result.strategy, TemplateMergeStrategy::TimestampWins);
    assert_eq!(result.value, json!("AD"));

    // ConcatenateUnique -- all three unique values combined
    let result = TemplateMergeService::resolve(
        TemplateMergeStrategy::ConcatenateUnique,
        &values,
        None,
        TemplateNullHandling::Merge,
    )
    .expect("concatenate_unique dispatch should work");
    assert_eq!(result.strategy, TemplateMergeStrategy::ConcatenateUnique);
    assert_eq!(result.value, json!(["HR", "AD", "Manual"]));

    // FirstWins -- HR should win (first in input order)
    let result = TemplateMergeService::resolve(
        TemplateMergeStrategy::FirstWins,
        &values,
        None,
        TemplateNullHandling::Merge,
    )
    .expect("first_wins dispatch should work");
    assert_eq!(result.strategy, TemplateMergeStrategy::FirstWins);
    assert_eq!(result.value, json!("HR"));

    // ManualOnly -- "manual" source value should win
    let result = TemplateMergeService::resolve(
        TemplateMergeStrategy::ManualOnly,
        &values,
        None,
        TemplateNullHandling::Merge,
    )
    .expect("manual_only dispatch should work");
    assert_eq!(result.strategy, TemplateMergeStrategy::ManualOnly);
    assert_eq!(result.value, json!("Manual"));
}
