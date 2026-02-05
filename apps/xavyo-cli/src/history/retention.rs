//! Retention policy for version history
//!
//! Implements the policy to keep only the last N versions (default 10),
//! automatically deleting older versions when the limit is exceeded.

use crate::error::CliResult;

use super::store::VersionHistory;

/// Enforce the retention policy by removing old versions
///
/// Keeps only the last `max_versions` versions, deleting the oldest ones
/// when the limit is exceeded.
pub fn enforce_retention(history: &mut VersionHistory) -> CliResult<()> {
    let max_versions = history.index().max_versions;
    let versions = history.index().versions.clone();

    // Check if we need to remove any versions
    if versions.len() <= max_versions {
        return Ok(());
    }

    // Calculate how many to remove
    let to_remove = versions.len() - max_versions;

    // Remove oldest versions (they are at the start of the sorted list)
    for &version in versions.iter().take(to_remove) {
        // Delete the version file
        let path = history.version_file_path(version);
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                // Log warning but continue - file might already be deleted
                eprintln!(
                    "Warning: Could not delete old version file {}: {}",
                    path.display(),
                    e
                );
            }
        }

        // Remove from index
        history.index_mut().remove_version(version);
    }

    // Save updated index
    history.save_index()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::config::XavyoConfig;
    use tempfile::TempDir;

    fn create_test_config() -> XavyoConfig {
        XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![],
        }
    }

    #[test]
    fn test_retention_no_action_under_limit() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path()).unwrap();

        let config = create_test_config();
        let mut history = VersionHistory::load(temp_dir.path()).unwrap();

        // Save 5 versions (under the default 10 limit)
        for i in 1..=5 {
            history
                .save_version(&config, Some(&format!("v{}.yaml", i)))
                .unwrap();
        }

        // Retention should not remove anything
        assert_eq!(history.available_versions().len(), 5);
        enforce_retention(&mut history).unwrap();
        assert_eq!(history.available_versions().len(), 5);
    }

    #[test]
    fn test_retention_removes_old_versions() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path()).unwrap();

        let config = create_test_config();
        let mut history = VersionHistory::load(temp_dir.path()).unwrap();

        // Modify max_versions to 3 for easier testing
        history.index_mut().max_versions = 3;

        // Save 5 versions (over the limit of 3)
        for i in 1..=5 {
            // Save without automatic retention to control when it runs
            let version_num = history.index_mut().add_version();
            let version = super::super::version::ConfigVersion::new(
                version_num,
                config.clone(),
                Some(format!("v{}.yaml", i)),
            );
            let path = history.version_file_path(version_num);
            let content = serde_json::to_string_pretty(&version).unwrap();
            std::fs::write(&path, content).unwrap();
        }
        history.save_index().unwrap();

        assert_eq!(history.available_versions().len(), 5);

        // Enforce retention
        enforce_retention(&mut history).unwrap();

        // Should have only 3 versions now
        assert_eq!(history.available_versions().len(), 3);

        // Should have kept the newest (3, 4, 5)
        assert!(history.index().has_version(3));
        assert!(history.index().has_version(4));
        assert!(history.index().has_version(5));

        // Should have removed oldest (1, 2)
        assert!(!history.index().has_version(1));
        assert!(!history.index().has_version(2));

        // Version files should be deleted
        assert!(!history.version_file_path(1).exists());
        assert!(!history.version_file_path(2).exists());

        // Newest version files should still exist
        assert!(history.version_file_path(3).exists());
        assert!(history.version_file_path(4).exists());
        assert!(history.version_file_path(5).exists());
    }

    #[test]
    fn test_retention_at_limit() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path()).unwrap();

        let config = create_test_config();
        let mut history = VersionHistory::load(temp_dir.path()).unwrap();

        // Modify max_versions to 3
        history.index_mut().max_versions = 3;

        // Save exactly 3 versions
        for i in 1..=3 {
            history
                .save_version(&config, Some(&format!("v{}.yaml", i)))
                .unwrap();
        }

        // Should have exactly 3 versions
        assert_eq!(history.available_versions().len(), 3);

        // Adding one more should trigger retention
        history.save_version(&config, Some("v4.yaml")).unwrap();

        // Should still have 3 versions
        assert_eq!(history.available_versions().len(), 3);

        // Should have versions 2, 3, 4 (oldest removed)
        assert!(!history.index().has_version(1));
        assert!(history.index().has_version(2));
        assert!(history.index().has_version(3));
        assert!(history.index().has_version(4));
    }
}
