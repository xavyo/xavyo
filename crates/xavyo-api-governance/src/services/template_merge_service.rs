//! Template merge resolution service for governance API (F058 - T053).
//!
//! Handles merge conflict resolution when data comes from multiple sources
//! using configurable strategies: source precedence, timestamp wins,
//! concatenate unique, first wins, and manual only.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovTemplateMergePolicy, GovTemplateMergePolicy, TemplateMergeStrategy,
    TemplateNullHandling, UpdateGovTemplateMergePolicy,
};
use xavyo_governance::error::{GovernanceError, Result};

/// A value from a specific data source, used in merge resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeValue {
    /// The source system that produced this value (e.g., "hr_system", "active_directory", "manual").
    pub source: String,
    /// The actual data value (can be any JSON type including null).
    pub value: serde_json::Value,
    /// When this value was last updated (used by `TimestampWins` strategy).
    pub timestamp: Option<DateTime<Utc>>,
}

/// Result of a merge resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeResolution {
    /// The resolved value.
    pub value: serde_json::Value,
    /// Which source(s) contributed to the resolved value.
    pub resolved_from: Vec<String>,
    /// The strategy used for resolution.
    pub strategy: TemplateMergeStrategy,
}

/// Error returned when merge resolution fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeError {
    /// Human-readable error message.
    pub message: String,
    /// The strategy that was attempted.
    pub strategy: TemplateMergeStrategy,
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Merge error ({}): {}", self.strategy, self.message)
    }
}

impl std::error::Error for MergeError {}

/// Service for resolving merge conflicts between multi-source data.
pub struct TemplateMergeService {
    pool: PgPool,
}

impl TemplateMergeService {
    /// Create a new template merge service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a merge policy by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovTemplateMergePolicy> {
        GovTemplateMergePolicy::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::Validation(format!("Merge policy not found: {id}")))
    }

    /// List merge policies for a template.
    pub async fn list_by_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateMergePolicy>> {
        GovTemplateMergePolicy::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Create a new merge policy.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        input: CreateGovTemplateMergePolicy,
    ) -> Result<GovTemplateMergePolicy> {
        GovTemplateMergePolicy::create(&self.pool, tenant_id, template_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a merge policy.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovTemplateMergePolicy,
    ) -> Result<GovTemplateMergePolicy> {
        GovTemplateMergePolicy::update(&self.pool, tenant_id, id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::Validation(format!("Merge policy not found: {id}")))
    }

    /// Delete a merge policy.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<bool> {
        GovTemplateMergePolicy::delete(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // Merge Resolution (stateless/static -- no DB required)
    // =========================================================================

    /// Resolve merge values using the source precedence strategy.
    ///
    /// Uses the ordered `source_precedence` list to determine which source's value wins.
    /// The first source in the list that has a non-null value (or any value if `PreserveEmpty`)
    /// is selected.
    pub fn resolve_source_precedence(
        values: &[MergeValue],
        source_precedence: &[String],
        null_handling: TemplateNullHandling,
    ) -> std::result::Result<MergeResolution, MergeError> {
        if values.is_empty() {
            return Err(MergeError {
                message: "No values to merge".to_string(),
                strategy: TemplateMergeStrategy::SourcePrecedence,
            });
        }

        for source in source_precedence {
            if let Some(mv) = values.iter().find(|v| &v.source == source) {
                match null_handling {
                    TemplateNullHandling::Merge => {
                        if !mv.value.is_null() {
                            return Ok(MergeResolution {
                                value: mv.value.clone(),
                                resolved_from: vec![mv.source.clone()],
                                strategy: TemplateMergeStrategy::SourcePrecedence,
                            });
                        }
                        // Null with Merge handling: skip and try next source
                    }
                    TemplateNullHandling::PreserveEmpty => {
                        return Ok(MergeResolution {
                            value: mv.value.clone(),
                            resolved_from: vec![mv.source.clone()],
                            strategy: TemplateMergeStrategy::SourcePrecedence,
                        });
                    }
                }
            }
        }

        // No source in precedence list had a usable value; try remaining values
        for mv in values {
            if !source_precedence.contains(&mv.source) {
                match null_handling {
                    TemplateNullHandling::Merge => {
                        if !mv.value.is_null() {
                            return Ok(MergeResolution {
                                value: mv.value.clone(),
                                resolved_from: vec![mv.source.clone()],
                                strategy: TemplateMergeStrategy::SourcePrecedence,
                            });
                        }
                    }
                    TemplateNullHandling::PreserveEmpty => {
                        return Ok(MergeResolution {
                            value: mv.value.clone(),
                            resolved_from: vec![mv.source.clone()],
                            strategy: TemplateMergeStrategy::SourcePrecedence,
                        });
                    }
                }
            }
        }

        Err(MergeError {
            message: "No source in precedence list has a usable value".to_string(),
            strategy: TemplateMergeStrategy::SourcePrecedence,
        })
    }

    /// Resolve merge values using the timestamp wins strategy.
    ///
    /// The value with the most recent timestamp is selected.
    /// Values without timestamps are ignored (unless they are the only values).
    /// When timestamps are equal, the first value in the input order wins (deterministic).
    pub fn resolve_timestamp_wins(
        values: &[MergeValue],
        null_handling: TemplateNullHandling,
    ) -> std::result::Result<MergeResolution, MergeError> {
        if values.is_empty() {
            return Err(MergeError {
                message: "No values to merge".to_string(),
                strategy: TemplateMergeStrategy::TimestampWins,
            });
        }

        let filtered: Vec<&MergeValue> = match null_handling {
            TemplateNullHandling::Merge => values.iter().filter(|v| !v.value.is_null()).collect(),
            TemplateNullHandling::PreserveEmpty => values.iter().collect(),
        };

        if filtered.is_empty() {
            return Err(MergeError {
                message: "All values are null".to_string(),
                strategy: TemplateMergeStrategy::TimestampWins,
            });
        }

        // Find the value with the most recent timestamp.
        // If timestamps are equal, the first one in order wins.
        let mut best: &MergeValue = filtered[0];
        for mv in filtered.iter().skip(1) {
            match (mv.timestamp, best.timestamp) {
                (Some(mv_ts), Some(best_ts)) => {
                    if mv_ts > best_ts {
                        best = mv;
                    }
                    // If equal, keep the current best (first wins for ties)
                }
                (Some(_), None) => {
                    best = mv;
                }
                (None, Some(_)) => {
                    // Keep best which has a timestamp
                }
                (None, None) => {
                    // Both without timestamps, keep first (deterministic)
                }
            }
        }

        Ok(MergeResolution {
            value: best.value.clone(),
            resolved_from: vec![best.source.clone()],
            strategy: TemplateMergeStrategy::TimestampWins,
        })
    }

    /// Resolve merge values using the concatenate unique strategy.
    ///
    /// Combines all unique values into a JSON array. Duplicates are removed.
    /// Null values are handled according to the `null_handling` parameter.
    pub fn resolve_concatenate_unique(
        values: &[MergeValue],
        null_handling: TemplateNullHandling,
    ) -> std::result::Result<MergeResolution, MergeError> {
        if values.is_empty() {
            return Err(MergeError {
                message: "No values to merge".to_string(),
                strategy: TemplateMergeStrategy::ConcatenateUnique,
            });
        }

        let mut unique_values: Vec<serde_json::Value> = Vec::new();
        let mut sources: Vec<String> = Vec::new();

        for mv in values {
            match null_handling {
                TemplateNullHandling::Merge => {
                    if mv.value.is_null() {
                        continue;
                    }
                }
                TemplateNullHandling::PreserveEmpty => {
                    // Include null values
                }
            }

            // Check for duplicates using JSON equality
            if !unique_values.contains(&mv.value) {
                unique_values.push(mv.value.clone());
                if !sources.contains(&mv.source) {
                    sources.push(mv.source.clone());
                }
            }
        }

        if unique_values.is_empty() {
            return Err(MergeError {
                message: "All values are null".to_string(),
                strategy: TemplateMergeStrategy::ConcatenateUnique,
            });
        }

        Ok(MergeResolution {
            value: serde_json::Value::Array(unique_values),
            resolved_from: sources,
            strategy: TemplateMergeStrategy::ConcatenateUnique,
        })
    }

    /// Resolve merge values using the first wins strategy.
    ///
    /// The first non-null value (in input order) is selected.
    pub fn resolve_first_wins(
        values: &[MergeValue],
        null_handling: TemplateNullHandling,
    ) -> std::result::Result<MergeResolution, MergeError> {
        if values.is_empty() {
            return Err(MergeError {
                message: "No values to merge".to_string(),
                strategy: TemplateMergeStrategy::FirstWins,
            });
        }

        for mv in values {
            match null_handling {
                TemplateNullHandling::Merge => {
                    if !mv.value.is_null() {
                        return Ok(MergeResolution {
                            value: mv.value.clone(),
                            resolved_from: vec![mv.source.clone()],
                            strategy: TemplateMergeStrategy::FirstWins,
                        });
                    }
                }
                TemplateNullHandling::PreserveEmpty => {
                    return Ok(MergeResolution {
                        value: mv.value.clone(),
                        resolved_from: vec![mv.source.clone()],
                        strategy: TemplateMergeStrategy::FirstWins,
                    });
                }
            }
        }

        Err(MergeError {
            message: "No non-null values found".to_string(),
            strategy: TemplateMergeStrategy::FirstWins,
        })
    }

    /// Resolve merge values using the manual only strategy.
    ///
    /// Only values from the "manual" source are accepted. All other sources are rejected.
    pub fn resolve_manual_only(
        values: &[MergeValue],
        null_handling: TemplateNullHandling,
    ) -> std::result::Result<MergeResolution, MergeError> {
        if values.is_empty() {
            return Err(MergeError {
                message: "No values to merge".to_string(),
                strategy: TemplateMergeStrategy::ManualOnly,
            });
        }

        for mv in values {
            if mv.source == "manual" {
                match null_handling {
                    TemplateNullHandling::Merge => {
                        if !mv.value.is_null() {
                            return Ok(MergeResolution {
                                value: mv.value.clone(),
                                resolved_from: vec!["manual".to_string()],
                                strategy: TemplateMergeStrategy::ManualOnly,
                            });
                        }
                    }
                    TemplateNullHandling::PreserveEmpty => {
                        return Ok(MergeResolution {
                            value: mv.value.clone(),
                            resolved_from: vec!["manual".to_string()],
                            strategy: TemplateMergeStrategy::ManualOnly,
                        });
                    }
                }
            }
        }

        Err(MergeError {
            message: "No value from manual source found".to_string(),
            strategy: TemplateMergeStrategy::ManualOnly,
        })
    }

    /// Resolve merge values using the specified strategy.
    ///
    /// This is a convenience dispatcher that calls the appropriate strategy-specific method.
    pub fn resolve(
        strategy: TemplateMergeStrategy,
        values: &[MergeValue],
        source_precedence: Option<&[String]>,
        null_handling: TemplateNullHandling,
    ) -> std::result::Result<MergeResolution, MergeError> {
        match strategy {
            TemplateMergeStrategy::SourcePrecedence => {
                let precedence = source_precedence.unwrap_or(&[]);
                Self::resolve_source_precedence(values, precedence, null_handling)
            }
            TemplateMergeStrategy::TimestampWins => {
                Self::resolve_timestamp_wins(values, null_handling)
            }
            TemplateMergeStrategy::ConcatenateUnique => {
                Self::resolve_concatenate_unique(values, null_handling)
            }
            TemplateMergeStrategy::FirstWins => Self::resolve_first_wins(values, null_handling),
            TemplateMergeStrategy::ManualOnly => Self::resolve_manual_only(values, null_handling),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_construction() {
        let _ = std::mem::size_of::<TemplateMergeService>();
    }

    #[test]
    fn test_merge_value_construction() {
        let mv = MergeValue {
            source: "hr_system".to_string(),
            value: serde_json::json!("John"),
            timestamp: Some(Utc::now()),
        };
        assert_eq!(mv.source, "hr_system");
        assert_eq!(mv.value, serde_json::json!("John"));
        assert!(mv.timestamp.is_some());
    }
}
