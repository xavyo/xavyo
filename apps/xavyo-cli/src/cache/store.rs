//! Cache store implementation for offline mode

use crate::cache::{CacheConfig, CacheEntry, CacheStatus, CachedResource};
use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use chrono::Utc;
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::PathBuf;

/// Cache keys for different resource types
pub const CACHE_KEY_AGENTS: &str = "agents";
pub const CACHE_KEY_TOOLS: &str = "tools";
pub const CACHE_KEY_STATUS: &str = "status";
pub const CACHE_KEY_WHOAMI: &str = "whoami";
pub const CACHE_KEY_TENANTS: &str = "tenants";

/// Trait for cache storage backends
pub trait CacheStore: Send + Sync {
    /// Get a cached entry by key
    fn get<T: DeserializeOwned>(&self, key: &str) -> CliResult<Option<CacheEntry<T>>>;

    /// Set a cached entry
    fn set<T: Serialize>(&self, key: &str, data: &T, ttl_seconds: u64) -> CliResult<()>;

    /// Delete a cached entry by key
    #[allow(dead_code)]
    fn delete(&self, key: &str) -> CliResult<()>;

    /// Clear all cached entries
    fn clear_all(&self) -> CliResult<usize>;

    /// Get the status of the cache
    fn status(&self) -> CliResult<CacheStatus>;

    /// Get the total cache size in bytes
    #[allow(dead_code)]
    fn cache_size(&self) -> CliResult<u64>;

    /// List all cached entry keys
    #[allow(dead_code)]
    fn list_entries(&self) -> CliResult<Vec<String>>;

    /// Check if cache exists for a given key
    #[allow(dead_code)]
    fn exists(&self, key: &str) -> bool;
}

/// File-based cache store implementation
pub struct FileCacheStore {
    cache_dir: PathBuf,
    config: CacheConfig,
}

impl FileCacheStore {
    /// Create a new file cache store
    pub fn new(paths: &ConfigPaths) -> CliResult<Self> {
        let config = CacheConfig::default();
        paths.ensure_cache_dir_exists()?;

        Ok(Self {
            cache_dir: paths.cache_dir.clone(),
            config,
        })
    }

    /// Create a new file cache store with custom config
    #[allow(dead_code)]
    pub fn with_config(paths: &ConfigPaths, config: CacheConfig) -> CliResult<Self> {
        paths.ensure_cache_dir_exists()?;

        Ok(Self {
            cache_dir: paths.cache_dir.clone(),
            config,
        })
    }

    /// Get the file path for a cache key
    fn cache_file_path(&self, key: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", key))
    }

    /// Get the default TTL from config
    pub fn default_ttl(&self) -> u64 {
        self.config.default_ttl_seconds
    }
}

impl CacheStore for FileCacheStore {
    fn get<T: DeserializeOwned>(&self, key: &str) -> CliResult<Option<CacheEntry<T>>> {
        let path = self.cache_file_path(key);

        if !path.exists() {
            return Ok(None);
        }

        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                // If we can't read the file, log and return None
                eprintln!(
                    "Warning: Failed to read cache file {}: {}",
                    path.display(),
                    e
                );
                // Try to delete the corrupted file
                let _ = fs::remove_file(&path);
                return Ok(None);
            }
        };

        match serde_json::from_str::<CacheEntry<T>>(&contents) {
            Ok(entry) => Ok(Some(entry)),
            Err(e) => {
                // If we can't parse the file, it's corrupted - delete and return None
                eprintln!(
                    "Warning: Cache file {} is corrupted ({}), clearing...",
                    path.display(),
                    e
                );
                let _ = fs::remove_file(&path);
                Ok(None)
            }
        }
    }

    fn set<T: Serialize>(&self, key: &str, data: &T, ttl_seconds: u64) -> CliResult<()> {
        let path = self.cache_file_path(key);
        let entry = CacheEntry::new(data, ttl_seconds);
        let contents = serde_json::to_string_pretty(&entry)?;

        fs::write(&path, contents).map_err(|e| {
            CliError::Cache(format!(
                "Failed to write cache file {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(())
    }

    fn delete(&self, key: &str) -> CliResult<()> {
        let path = self.cache_file_path(key);

        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                CliError::Cache(format!(
                    "Failed to delete cache file {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        Ok(())
    }

    fn clear_all(&self) -> CliResult<usize> {
        let mut count = 0;

        if !self.cache_dir.exists() {
            return Ok(0);
        }

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "json") && fs::remove_file(&path).is_ok() {
                count += 1;
            }
        }

        Ok(count)
    }

    fn status(&self) -> CliResult<CacheStatus> {
        let mut total_size = 0u64;
        let mut cached_resources = Vec::new();

        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().is_some_and(|ext| ext == "json") {
                    let metadata = entry.metadata()?;
                    let size = metadata.len();
                    total_size += size;

                    // Extract resource type from filename
                    if let Some(stem) = path.file_stem() {
                        let resource_type = stem.to_string_lossy().to_string();

                        // Try to read the cached_at and check expiry
                        let (cached_at, is_expired) = if let Ok(contents) =
                            fs::read_to_string(&path)
                        {
                            // Parse just the metadata fields
                            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents)
                            {
                                let cached_at = value
                                    .get("cached_at")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                    .map(|dt| dt.with_timezone(&Utc))
                                    .unwrap_or_else(Utc::now);

                                let ttl = value
                                    .get("ttl_seconds")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(self.config.default_ttl_seconds);

                                let expiry = cached_at + chrono::Duration::seconds(ttl as i64);
                                let is_expired = Utc::now() > expiry;

                                (cached_at, is_expired)
                            } else {
                                (Utc::now(), true)
                            }
                        } else {
                            (Utc::now(), true)
                        };

                        cached_resources.push(CachedResource {
                            resource_type,
                            cached_at,
                            is_expired,
                            size_bytes: size,
                        });
                    }
                }
            }
        }

        Ok(CacheStatus {
            total_size_bytes: total_size,
            entry_count: cached_resources.len(),
            cached_resources,
            cache_dir: self.cache_dir.clone(),
            default_ttl_seconds: self.config.default_ttl_seconds,
        })
    }

    fn cache_size(&self) -> CliResult<u64> {
        let mut total = 0u64;

        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                if entry.path().extension().is_some_and(|ext| ext == "json") {
                    total += entry.metadata()?.len();
                }
            }
        }

        Ok(total)
    }

    fn list_entries(&self) -> CliResult<Vec<String>> {
        let mut entries = Vec::new();

        if self.cache_dir.exists() {
            for entry in fs::read_dir(&self.cache_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().is_some_and(|ext| ext == "json") {
                    if let Some(stem) = path.file_stem() {
                        entries.push(stem.to_string_lossy().to_string());
                    }
                }
            }
        }

        Ok(entries)
    }

    fn exists(&self, key: &str) -> bool {
        self.cache_file_path(key).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_paths() -> (TempDir, ConfigPaths) {
        let temp_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp_dir.path().to_path_buf(),
            config_file: temp_dir.path().join("config.json"),
            session_file: temp_dir.path().join("session.json"),
            credentials_file: temp_dir.path().join("credentials.enc"),
            cache_dir: temp_dir.path().join("cache"),
            history_file: temp_dir.path().join("shell_history"),
            version_history_dir: temp_dir.path().join("history"),
        };
        (temp_dir, paths)
    }

    #[test]
    fn test_file_cache_store_set_and_get() {
        let (_temp_dir, paths) = create_test_paths();
        let store = FileCacheStore::new(&paths).unwrap();

        // Set a value
        store
            .set("test_key", &"test_value".to_string(), 3600)
            .unwrap();

        // Get the value back
        let entry: Option<CacheEntry<String>> = store.get("test_key").unwrap();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().data, "test_value");
    }

    #[test]
    fn test_file_cache_store_get_nonexistent() {
        let (_temp_dir, paths) = create_test_paths();
        let store = FileCacheStore::new(&paths).unwrap();

        let entry: Option<CacheEntry<String>> = store.get("nonexistent").unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn test_file_cache_store_delete() {
        let (_temp_dir, paths) = create_test_paths();
        let store = FileCacheStore::new(&paths).unwrap();

        store.set("to_delete", &"value".to_string(), 3600).unwrap();
        assert!(store.exists("to_delete"));

        store.delete("to_delete").unwrap();
        assert!(!store.exists("to_delete"));
    }

    #[test]
    fn test_file_cache_store_clear_all() {
        let (_temp_dir, paths) = create_test_paths();
        let store = FileCacheStore::new(&paths).unwrap();

        store.set("key1", &"value1".to_string(), 3600).unwrap();
        store.set("key2", &"value2".to_string(), 3600).unwrap();

        let count = store.clear_all().unwrap();
        assert_eq!(count, 2);
        assert!(!store.exists("key1"));
        assert!(!store.exists("key2"));
    }

    #[test]
    fn test_file_cache_store_list_entries() {
        let (_temp_dir, paths) = create_test_paths();
        let store = FileCacheStore::new(&paths).unwrap();

        store.set("agents", &vec!["agent1"], 3600).unwrap();
        store.set("tools", &vec!["tool1"], 3600).unwrap();

        let entries = store.list_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&"agents".to_string()));
        assert!(entries.contains(&"tools".to_string()));
    }

    #[test]
    fn test_file_cache_store_status() {
        let (_temp_dir, paths) = create_test_paths();
        let store = FileCacheStore::new(&paths).unwrap();

        store.set("agents", &vec!["agent1"], 3600).unwrap();

        let status = store.status().unwrap();
        assert_eq!(status.entry_count, 1);
        assert!(status.total_size_bytes > 0);
        assert_eq!(status.cached_resources.len(), 1);
        assert_eq!(status.cached_resources[0].resource_type, "agents");
    }
}
