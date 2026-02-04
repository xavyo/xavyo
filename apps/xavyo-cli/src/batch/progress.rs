//! Progress reporting for batch operations
//!
//! Provides a progress bar wrapper for batch operations using indicatif.

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Progress indicator for batch operations
pub struct BatchProgress {
    /// The underlying progress bar
    bar: ProgressBar,
    /// Whether this is a dry-run (affects display)
    #[allow(dead_code)]
    dry_run: bool,
}

impl BatchProgress {
    /// Create a new progress indicator for batch operations
    pub fn new(total: u64, operation: &str, dry_run: bool) -> Self {
        let bar = ProgressBar::new(total);

        let template = if dry_run {
            "{spinner:.yellow} {msg} [{bar:40.yellow/blue}] {pos}/{len}"
        } else {
            "{spinner:.green} {msg} [{bar:40.cyan/blue}] {pos}/{len}"
        };

        bar.set_style(
            ProgressStyle::default_bar()
                .template(template)
                .expect("Invalid progress bar template")
                .progress_chars("█▓▒░"),
        );

        let prefix = if dry_run {
            format!("(dry-run) {} ", operation)
        } else {
            format!("{} ", operation)
        };

        bar.set_message(prefix);
        bar.enable_steady_tick(Duration::from_millis(100));

        Self { bar, dry_run }
    }

    /// Increment the progress by one
    pub fn inc(&self) {
        self.bar.inc(1);
    }

    /// Set the current message
    #[allow(dead_code)]
    pub fn set_message(&self, msg: &str) {
        let prefix = if self.dry_run {
            format!("(dry-run) {}", msg)
        } else {
            msg.to_string()
        };
        self.bar.set_message(prefix);
    }

    /// Mark the progress as finished with a message
    #[allow(dead_code)]
    pub fn finish_with_message(&self, msg: &str) {
        self.bar.finish_with_message(msg.to_string());
    }

    /// Finish and clear the progress bar
    pub fn finish_and_clear(&self) {
        self.bar.finish_and_clear();
    }

    /// Check if the operation should be aborted (for Ctrl+C handling)
    #[allow(dead_code)]
    pub fn is_finished(&self) -> bool {
        self.bar.is_finished()
    }
}

/// Create a spinner for indeterminate operations
#[allow(dead_code)]
pub fn create_spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("Invalid spinner template"),
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_progress_new() {
        let progress = BatchProgress::new(10, "Creating agents...", false);
        assert!(!progress.dry_run);
        assert!(!progress.is_finished());
    }

    #[test]
    fn test_batch_progress_dry_run() {
        let progress = BatchProgress::new(5, "Creating agents...", true);
        assert!(progress.dry_run);
    }

    #[test]
    fn test_batch_progress_inc() {
        let progress = BatchProgress::new(3, "Test", false);
        progress.inc();
        progress.inc();
        // Should not panic
    }

    #[test]
    fn test_batch_progress_finish() {
        let progress = BatchProgress::new(2, "Test", false);
        progress.inc();
        progress.inc();
        progress.finish_with_message("Done!");
        assert!(progress.is_finished());
    }

    #[test]
    fn test_create_spinner() {
        let spinner = create_spinner("Loading...");
        assert!(!spinner.is_finished());
        spinner.finish();
        assert!(spinner.is_finished());
    }
}
