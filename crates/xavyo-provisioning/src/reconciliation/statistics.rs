//! Run statistics tracking for reconciliation.
//!
//! Tracks and aggregates statistics during reconciliation execution.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::RwLock;
use std::time::Instant;

use super::types::{ActionType, DiscrepancyType};

/// Statistics for a reconciliation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunStatistics {
    /// Total number of accounts to process.
    #[serde(default)]
    pub accounts_total: u32,
    /// Number of accounts processed so far.
    #[serde(default)]
    pub accounts_processed: u32,
    /// Total discrepancies found.
    #[serde(default)]
    pub discrepancies_found: u32,
    /// Discrepancies broken down by type.
    #[serde(default)]
    pub discrepancies_by_type: HashMap<String, u32>,
    /// Actions taken broken down by type.
    #[serde(default)]
    pub actions_taken: HashMap<String, u32>,
    /// Total duration in seconds.
    #[serde(default)]
    pub duration_seconds: u64,
}

impl RunStatistics {
    /// Create new empty statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate progress percentage.
    #[must_use]
    pub fn progress_percentage(&self) -> f64 {
        if self.accounts_total == 0 {
            0.0
        } else {
            (f64::from(self.accounts_processed) / f64::from(self.accounts_total)) * 100.0
        }
    }

    /// Get count for a specific discrepancy type.
    #[must_use]
    pub fn discrepancy_count(&self, discrepancy_type: DiscrepancyType) -> u32 {
        self.discrepancies_by_type
            .get(&discrepancy_type.to_string())
            .copied()
            .unwrap_or(0)
    }

    /// Get count for a specific action type.
    #[must_use]
    pub fn action_count(&self, action_type: ActionType) -> u32 {
        self.actions_taken
            .get(&action_type.to_string())
            .copied()
            .unwrap_or(0)
    }

    /// Merge with another statistics instance.
    pub fn merge(&mut self, other: &RunStatistics) {
        self.accounts_processed += other.accounts_processed;
        self.discrepancies_found += other.discrepancies_found;

        for (key, value) in &other.discrepancies_by_type {
            *self.discrepancies_by_type.entry(key.clone()).or_insert(0) += value;
        }

        for (key, value) in &other.actions_taken {
            *self.actions_taken.entry(key.clone()).or_insert(0) += value;
        }
    }
}

/// Thread-safe tracker for accumulating statistics during a run.
pub struct StatisticsTracker {
    /// Total accounts to process.
    accounts_total: AtomicU32,
    /// Accounts processed.
    accounts_processed: AtomicU32,
    /// Total discrepancies found.
    discrepancies_found: AtomicU32,
    /// Discrepancies by type.
    discrepancies_by_type: RwLock<HashMap<DiscrepancyType, u32>>,
    /// Actions taken by type.
    actions_taken: RwLock<HashMap<ActionType, u32>>,
    /// Start time for duration calculation.
    start_time: Instant,
}

impl StatisticsTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            accounts_total: AtomicU32::new(0),
            accounts_processed: AtomicU32::new(0),
            discrepancies_found: AtomicU32::new(0),
            discrepancies_by_type: RwLock::new(HashMap::new()),
            actions_taken: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }

    /// Create tracker with initial total.
    #[must_use]
    pub fn with_total(total: u32) -> Self {
        let tracker = Self::new();
        tracker.accounts_total.store(total, Ordering::SeqCst);
        tracker
    }

    /// Set total accounts to process.
    pub fn set_total(&self, total: u32) {
        self.accounts_total.store(total, Ordering::SeqCst);
    }

    /// Increment processed count.
    pub fn increment_processed(&self, count: u32) {
        self.accounts_processed.fetch_add(count, Ordering::SeqCst);
    }

    /// Record a discrepancy.
    pub fn record_discrepancy(&self, discrepancy_type: DiscrepancyType) {
        self.discrepancies_found.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut map) = self.discrepancies_by_type.write() {
            *map.entry(discrepancy_type).or_insert(0) += 1;
        }
    }

    /// Record multiple discrepancies of the same type.
    pub fn record_discrepancies(&self, discrepancy_type: DiscrepancyType, count: u32) {
        self.discrepancies_found.fetch_add(count, Ordering::SeqCst);
        if let Ok(mut map) = self.discrepancies_by_type.write() {
            *map.entry(discrepancy_type).or_insert(0) += count;
        }
    }

    /// Record an action taken.
    pub fn record_action(&self, action_type: ActionType) {
        if let Ok(mut map) = self.actions_taken.write() {
            *map.entry(action_type).or_insert(0) += 1;
        }
    }

    /// Get current processed count.
    pub fn processed_count(&self) -> u32 {
        self.accounts_processed.load(Ordering::SeqCst)
    }

    /// Get total accounts.
    pub fn total_count(&self) -> u32 {
        self.accounts_total.load(Ordering::SeqCst)
    }

    /// Calculate current progress percentage.
    pub fn progress_percentage(&self) -> f64 {
        let total = self.accounts_total.load(Ordering::SeqCst);
        if total == 0 {
            return 0.0;
        }
        let processed = self.accounts_processed.load(Ordering::SeqCst);
        (f64::from(processed) / f64::from(total)) * 100.0
    }

    /// Get elapsed duration in seconds.
    pub fn elapsed_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Snapshot current statistics.
    pub fn snapshot(&self) -> RunStatistics {
        let discrepancies_by_type = self
            .discrepancies_by_type
            .read()
            .map(|map| map.iter().map(|(k, v)| (k.to_string(), *v)).collect())
            .unwrap_or_default();

        let actions_taken = self
            .actions_taken
            .read()
            .map(|map| map.iter().map(|(k, v)| (k.to_string(), *v)).collect())
            .unwrap_or_default();

        RunStatistics {
            accounts_total: self.accounts_total.load(Ordering::SeqCst),
            accounts_processed: self.accounts_processed.load(Ordering::SeqCst),
            discrepancies_found: self.discrepancies_found.load(Ordering::SeqCst),
            discrepancies_by_type,
            actions_taken,
            duration_seconds: self.elapsed_seconds(),
        }
    }
}

impl Default for StatisticsTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_statistics_default() {
        let stats = RunStatistics::default();
        assert_eq!(stats.accounts_total, 0);
        assert_eq!(stats.accounts_processed, 0);
        assert_eq!(stats.discrepancies_found, 0);
        assert!(stats.discrepancies_by_type.is_empty());
        assert!(stats.actions_taken.is_empty());
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_run_statistics_progress() {
        let mut stats = RunStatistics::default();
        stats.accounts_total = 100;
        stats.accounts_processed = 50;
        assert!((stats.progress_percentage() - 50.0).abs() < f64::EPSILON);

        stats.accounts_processed = 0;
        assert!((stats.progress_percentage() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_run_statistics_zero_total_progress() {
        let stats = RunStatistics::default();
        assert!((stats.progress_percentage() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_statistics_tracker_basic() {
        let tracker = StatisticsTracker::with_total(100);
        assert_eq!(tracker.total_count(), 100);
        assert_eq!(tracker.processed_count(), 0);

        tracker.increment_processed(25);
        assert_eq!(tracker.processed_count(), 25);
        assert!((tracker.progress_percentage() - 25.0).abs() < f64::EPSILON);

        tracker.increment_processed(25);
        assert_eq!(tracker.processed_count(), 50);
    }

    #[test]
    fn test_statistics_tracker_discrepancies() {
        let tracker = StatisticsTracker::new();

        tracker.record_discrepancy(DiscrepancyType::Missing);
        tracker.record_discrepancy(DiscrepancyType::Missing);
        tracker.record_discrepancy(DiscrepancyType::Orphan);

        let stats = tracker.snapshot();
        assert_eq!(stats.discrepancies_found, 3);
        assert_eq!(stats.discrepancy_count(DiscrepancyType::Missing), 2);
        assert_eq!(stats.discrepancy_count(DiscrepancyType::Orphan), 1);
        assert_eq!(stats.discrepancy_count(DiscrepancyType::Mismatch), 0);
    }

    #[test]
    fn test_statistics_tracker_actions() {
        let tracker = StatisticsTracker::new();

        tracker.record_action(ActionType::Create);
        tracker.record_action(ActionType::Create);
        tracker.record_action(ActionType::Update);

        let stats = tracker.snapshot();
        assert_eq!(stats.action_count(ActionType::Create), 2);
        assert_eq!(stats.action_count(ActionType::Update), 1);
        assert_eq!(stats.action_count(ActionType::Delete), 0);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_run_statistics_merge() {
        let mut stats1 = RunStatistics::default();
        stats1.accounts_processed = 50;
        stats1.discrepancies_found = 5;
        stats1
            .discrepancies_by_type
            .insert("missing".to_string(), 3);
        stats1.discrepancies_by_type.insert("orphan".to_string(), 2);

        let mut stats2 = RunStatistics::default();
        stats2.accounts_processed = 50;
        stats2.discrepancies_found = 5;
        stats2
            .discrepancies_by_type
            .insert("missing".to_string(), 2);
        stats2
            .discrepancies_by_type
            .insert("mismatch".to_string(), 3);

        stats1.merge(&stats2);

        assert_eq!(stats1.accounts_processed, 100);
        assert_eq!(stats1.discrepancies_found, 10);
        assert_eq!(stats1.discrepancies_by_type.get("missing"), Some(&5));
        assert_eq!(stats1.discrepancies_by_type.get("orphan"), Some(&2));
        assert_eq!(stats1.discrepancies_by_type.get("mismatch"), Some(&3));
    }
}
