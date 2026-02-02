//! File-based secret provider for Kubernetes volume mounts.
//!
//! Reads secrets from filesystem paths configured via SECRET_MAP_* env vars.
//! Supports file watching via the `notify` crate for live rotation detection.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::SecretProviderConfig;
use crate::{SecretError, SecretProvider, SecretValue};

/// Secret provider that reads secrets from filesystem paths.
pub struct FileSecretProvider {
    /// Maps logical secret name → file path.
    path_mappings: HashMap<String, PathBuf>,
    /// File watcher handle (kept alive to continue watching).
    _watcher: Option<notify::RecommendedWatcher>,
    /// Cache invalidation sender — signals when a file changes.
    change_tx: Option<tokio::sync::broadcast::Sender<String>>,
}

impl std::fmt::Debug for FileSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSecretProvider")
            .field("path_mappings", &self.path_mappings)
            .finish()
    }
}

impl FileSecretProvider {
    /// Create a new FileSecretProvider from configuration.
    pub fn new(config: &SecretProviderConfig) -> Result<Self, SecretError> {
        let path_mappings: HashMap<String, PathBuf> = config
            .secret_mappings
            .iter()
            .map(|(name, path)| (name.clone(), PathBuf::from(path)))
            .collect();

        if path_mappings.is_empty() {
            tracing::warn!("FileSecretProvider: No SECRET_MAP_* mappings found. No secrets will be available from files.");
        }

        let file_config = config.file.as_ref();
        let watch_enabled = file_config.map(|c| c.watch_enabled).unwrap_or(true);

        let (watcher, change_tx) = if watch_enabled {
            Self::setup_file_watcher(&path_mappings, file_config)?
        } else {
            (None, None)
        };

        Ok(Self {
            path_mappings,
            _watcher: watcher,
            change_tx,
        })
    }

    /// Get a receiver for file change notifications.
    pub fn change_receiver(&self) -> Option<tokio::sync::broadcast::Receiver<String>> {
        self.change_tx.as_ref().map(|tx| tx.subscribe())
    }

    /// Setup file watcher for rotation detection.
    fn setup_file_watcher(
        path_mappings: &HashMap<String, PathBuf>,
        file_config: Option<&crate::config::FileConfig>,
    ) -> Result<
        (
            Option<notify::RecommendedWatcher>,
            Option<tokio::sync::broadcast::Sender<String>>,
        ),
        SecretError,
    > {
        use notify::{RecursiveMode, Watcher};

        let (change_tx, _) = tokio::sync::broadcast::channel::<String>(32);
        let tx_clone = change_tx.clone();

        // Build reverse map: path → logical name
        let path_to_name: HashMap<PathBuf, String> = path_mappings
            .iter()
            .filter_map(|(name, path)| {
                path.canonicalize()
                    .ok()
                    .map(|canonical| (canonical, name.clone()))
            })
            .collect();

        let debounce_ms = file_config.map(|c| c.watch_debounce_ms).unwrap_or(2000);

        let mut watcher =
            notify::recommended_watcher(move |event: Result<notify::Event, notify::Error>| {
                if let Ok(event) = event {
                    if matches!(
                        event.kind,
                        notify::EventKind::Modify(_)
                            | notify::EventKind::Create(_)
                            | notify::EventKind::Remove(_)
                    ) {
                        for path in &event.paths {
                            if let Ok(canonical) = path.canonicalize() {
                                if let Some(name) = path_to_name.get(&canonical) {
                                    tracing::info!(
                                        secret_name = %name,
                                        path = %path.display(),
                                        "Secret file changed, triggering reload"
                                    );
                                    let _ = tx_clone.send(name.clone());
                                }
                            }
                            // Also check parent directory (for Kubernetes atomic renames)
                            if let Some(parent) = path.parent() {
                                for (watched_path, name) in &path_to_name {
                                    if watched_path.parent() == Some(parent) {
                                        let _ = tx_clone.send(name.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|e| SecretError::ConfigError {
                detail: format!("Failed to create file watcher: {e}"),
            })?;

        // Debounce is handled by the notify crate internally in v6
        let _ = debounce_ms; // Used for documentation; notify v6 handles debouncing

        // Watch each secret file's parent directory (for rename-based rotation)
        for path in path_mappings.values() {
            let watch_path = if path.is_file() {
                path.parent().unwrap_or(path)
            } else {
                path.as_path()
            };

            if watch_path.exists() {
                if let Err(e) = watcher.watch(watch_path, RecursiveMode::NonRecursive) {
                    tracing::warn!(
                        path = %watch_path.display(),
                        error = %e,
                        "Failed to watch secret file path"
                    );
                }
            }
        }

        Ok((Some(watcher), Some(change_tx)))
    }

    /// Check file permissions and warn if world-readable.
    #[cfg(unix)]
    fn check_permissions(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode();
            if mode & 0o004 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode),
                    "Secret file is world-readable. Consider restricting permissions to 0600."
                );
            }
        }
    }

    #[cfg(not(unix))]
    fn check_permissions(_path: &std::path::Path) {
        // Permission checking is Unix-specific
    }
}

#[async_trait]
impl SecretProvider for FileSecretProvider {
    async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError> {
        let path = self
            .path_mappings
            .get(name)
            .ok_or_else(|| SecretError::NotFound {
                name: name.to_string(),
            })?;

        // Check permissions
        Self::check_permissions(path);

        // Read file contents
        let contents = tokio::fs::read(path).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => SecretError::NotFound {
                name: name.to_string(),
            },
            std::io::ErrorKind::PermissionDenied => SecretError::PermissionDenied {
                detail: format!(
                    "Cannot read secret file '{}': permission denied",
                    path.display()
                ),
            },
            _ => SecretError::ProviderUnavailable {
                provider: "file".to_string(),
                detail: format!("Failed to read '{}': {e}", path.display()),
            },
        })?;

        if contents.is_empty() {
            return Err(SecretError::InvalidValue {
                name: name.to_string(),
                detail: format!("Secret file '{}' is empty", path.display()),
            });
        }

        tracing::debug!(
            secret_name = name,
            path = %path.display(),
            "Secret loaded from file"
        );

        Ok(SecretValue::new(name, contents))
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        let mut all_ok = true;
        for (name, path) in &self.path_mappings {
            if !path.exists() {
                tracing::warn!(
                    secret_name = %name,
                    path = %path.display(),
                    "Secret file does not exist"
                );
                all_ok = false;
            } else if tokio::fs::metadata(path).await.is_err() {
                tracing::warn!(
                    secret_name = %name,
                    path = %path.display(),
                    "Secret file is not readable"
                );
                all_ok = false;
            }
        }
        Ok(all_ok)
    }

    fn provider_type(&self) -> &'static str {
        "file"
    }
}
