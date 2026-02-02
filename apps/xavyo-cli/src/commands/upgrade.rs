//! CLI upgrade command implementation
//!
//! Checks for new releases on GitHub, downloads the appropriate binary,
//! verifies its integrity via SHA-256 checksum, and atomically replaces
//! the current binary.

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Args;
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use semver::Version;
use sha2::{Digest, Sha256};

use crate::error::{CliError, CliResult};
use crate::models::platform::{PackageManager, Platform};
use crate::models::release::{GitHubRelease, Release};
use crate::models::upgrade::{UpgradeCheckJson, UpgradeInfo, UpgradeResultJson};

/// GitHub repository info for releases
const GITHUB_OWNER: &str = "xavyo";
const GITHUB_REPO: &str = "xavyo";

/// Arguments for the upgrade command
#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Check for updates without installing
    #[arg(long, short = 'c')]
    pub check: bool,

    /// Force reinstall even if already on latest version
    #[arg(long, short = 'f')]
    pub force: bool,

    /// Skip confirmation prompt (for scripted use)
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Output in JSON format (for scripted use)
    #[arg(long, short = 'j')]
    pub json: bool,
}

/// Execute the upgrade command
pub async fn execute(args: UpgradeArgs) -> CliResult<()> {
    // Get current version from Cargo.toml at compile time
    let current_version = env!("CARGO_PKG_VERSION");
    let current = Version::parse(current_version)
        .map_err(|e| CliError::InvalidVersion(format!("{}: {}", current_version, e)))?;

    // Detect platform
    let platform = Platform::current();
    if !platform.is_supported() {
        return Err(CliError::UnsupportedPlatform {
            os: platform.os.clone(),
            arch: platform.arch.clone(),
        });
    }

    // Check for package manager installation
    let binary_path = get_current_binary_path()?;
    let pkg_manager = PackageManager::detect(&binary_path);

    if pkg_manager.blocks_self_upgrade() && !args.force {
        if let Some(cmd) = pkg_manager.upgrade_command() {
            if args.json {
                let result = UpgradeResultJson::failure(
                    current_version,
                    &format!(
                        "CLI installed via package manager. Use: {}. Or run with --force to override.",
                        cmd
                    ),
                );
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }

            println!("Warning: xavyo appears to be installed via a package manager\n");
            println!("To maintain consistent package management, use:");
            println!("  {}\n", cmd);
            println!("To upgrade anyway, run:");
            println!("  xavyo upgrade --force");
            return Ok(());
        }
    }

    // Fetch latest release
    if !args.json {
        println!("Checking for updates...");
    }

    let client = create_http_client()?;
    let release = fetch_latest_release(&client).await?;

    // Compare versions
    let update_available = release.version > current || args.force;
    let upgrade_info = if update_available {
        let asset_name = platform.asset_name(&release.version.to_string());
        let asset = release.find_asset(&asset_name).ok_or_else(|| {
            CliError::NoAssetFound(format!(
                "{} (platform: {})",
                asset_name, platform.asset_suffix
            ))
        })?;

        UpgradeInfo::available(current.clone(), release.clone(), asset.download_url.clone())
    } else {
        UpgradeInfo::up_to_date(current.clone())
    };

    // Handle check-only mode
    if args.check {
        return handle_check_only(&upgrade_info, args.json);
    }

    // Handle already up-to-date
    if !update_available {
        if args.json {
            let result = UpgradeResultJson::up_to_date(current_version);
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!("Already on latest version ({})", current_version);
        }
        return Ok(());
    }

    // Display release info and confirm upgrade
    if !args.json {
        println!("Current version: {}", current_version);
        println!("Latest version:  {}\n", release.version);

        // Display release notes
        display_release_notes(&release);

        // Confirm upgrade (unless --yes)
        if !args.yes {
            let proceed = Confirm::new()
                .with_prompt("Proceed with upgrade?")
                .default(false)
                .interact()
                .map_err(|e| CliError::Io(e.to_string()))?;

            if !proceed {
                println!("Upgrade cancelled.");
                return Err(CliError::UpgradeAborted);
            }
        }
    }

    // Perform the upgrade
    let download_url = upgrade_info
        .download_url
        .as_ref()
        .ok_or_else(|| CliError::NoAssetFound(platform.asset_suffix.clone()))?;

    let asset_name = platform.asset_name(&release.version.to_string());
    let expected_size = release.find_asset(&asset_name).map(|a| a.size).unwrap_or(0);

    // Fetch checksum
    let checksum = fetch_checksum(&client, &release, &asset_name).await?;

    // Download with progress
    let temp_path = download_with_progress(&client, download_url, expected_size, args.json).await?;

    // Verify checksum
    if !args.json {
        println!("Verifying checksum...");
    }
    verify_checksum(&temp_path, &checksum)?;

    // Install the new binary
    if !args.json {
        println!("Installing...");
    }
    atomic_replace_binary(&temp_path, &binary_path)?;

    // Report success
    if args.json {
        let result = UpgradeResultJson::success(current_version, &release.version.to_string());
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("✓ Successfully upgraded to v{}", release.version);
    }

    Ok(())
}

/// Handle check-only mode output
fn handle_check_only(info: &UpgradeInfo, json: bool) -> CliResult<()> {
    if json {
        let output = UpgradeCheckJson::from(info);
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if info.update_available {
        println!(
            "Update available: {} → {}",
            info.current_version, info.latest_version
        );
        println!("Run 'xavyo upgrade' to install");
    } else {
        println!("Already on latest version ({})", info.current_version);
    }
    Ok(())
}

/// Display release notes to the user
fn display_release_notes(release: &Release) {
    println!("Release notes:");
    if let Some(body) = &release.body {
        // Indent the release notes
        for line in body.lines() {
            println!("  {}", line);
        }
        println!();
    } else {
        println!("  No release notes available.\n");
    }
}

/// Create HTTP client with appropriate headers
fn create_http_client() -> CliResult<Client> {
    Client::builder()
        .user_agent(format!("xavyo-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CliError::Network(e.to_string()))
}

/// Fetch the latest release from GitHub
async fn fetch_latest_release(client: &Client) -> CliResult<Release> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        GITHUB_OWNER, GITHUB_REPO
    );

    let response = client
        .get(&url)
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await?;

    if response.status() == 404 {
        return Err(CliError::NotFound("No releases found".to_string()));
    }

    if !response.status().is_success() {
        return Err(CliError::Api {
            status: response.status().as_u16(),
            message: "Failed to fetch latest release".to_string(),
        });
    }

    let gh_release: GitHubRelease = response
        .json()
        .await
        .map_err(|e| CliError::Network(format!("Failed to parse release: {}", e)))?;

    Release::try_from(gh_release)
        .map_err(|e| CliError::InvalidVersion(format!("Invalid release version: {}", e)))
}

/// Fetch checksum for the given asset
async fn fetch_checksum(client: &Client, release: &Release, asset_name: &str) -> CliResult<String> {
    let checksums_asset = release
        .find_checksums()
        .ok_or_else(|| CliError::NotFound("checksums.sha256 file not found".to_string()))?;

    let response = client.get(&checksums_asset.download_url).send().await?;

    if !response.status().is_success() {
        return Err(CliError::Network(
            "Failed to download checksums".to_string(),
        ));
    }

    let checksums_content = response.text().await?;

    // Parse checksums file (format: "hash  filename")
    for line in checksums_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == asset_name {
            return Ok(parts[0].to_string());
        }
    }

    Err(CliError::NotFound(format!(
        "Checksum for {} not found",
        asset_name
    )))
}

/// Download file with progress bar
async fn download_with_progress(
    client: &Client,
    url: &str,
    expected_size: u64,
    silent: bool,
) -> CliResult<PathBuf> {
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(CliError::Network(format!(
            "Download failed with status {}",
            response.status()
        )));
    }

    let total_size = response
        .content_length()
        .unwrap_or(expected_size)
        .max(expected_size);

    // Create temp file
    let temp_dir = env::temp_dir();
    let temp_path = temp_dir.join(format!("xavyo-upgrade-{}", uuid::Uuid::new_v4()));

    let mut file = File::create(&temp_path).map_err(|e| CliError::Io(e.to_string()))?;

    // Setup progress bar
    let progress = if !silent && total_size > 0 {
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} Downloading... [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec})",
                )
                .unwrap()
                .progress_chars("█▓░"),
        );
        Some(pb)
    } else {
        None
    };

    // Download in chunks
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| CliError::Network(e.to_string()))?;
        file.write_all(&chunk)
            .map_err(|e| CliError::Io(e.to_string()))?;
        downloaded += chunk.len() as u64;

        if let Some(ref pb) = progress {
            pb.set_position(downloaded);
        }
    }

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    Ok(temp_path)
}

/// Verify file checksum
fn verify_checksum(file_path: &PathBuf, expected: &str) -> CliResult<()> {
    let mut file = File::open(file_path).map_err(|e| CliError::Io(e.to_string()))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| CliError::Io(e.to_string()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let actual = format!("{:x}", hasher.finalize());

    if actual.to_lowercase() != expected.to_lowercase() {
        // Clean up temp file
        let _ = fs::remove_file(file_path);
        return Err(CliError::ChecksumMismatch {
            expected: expected.to_string(),
            actual,
        });
    }

    Ok(())
}

/// Get the path to the current binary
fn get_current_binary_path() -> CliResult<String> {
    env::current_exe()
        .map_err(|e| CliError::Io(format!("Could not determine binary path: {}", e)))?
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| CliError::Io("Binary path contains invalid UTF-8".to_string()))
}

/// Atomically replace the current binary with the new one
fn atomic_replace_binary(new_binary: &PathBuf, target_path: &str) -> CliResult<()> {
    let target = PathBuf::from(target_path);
    let backup_path = target.with_extension("old");

    // Make the new binary executable (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(new_binary)
            .map_err(|e| CliError::Io(e.to_string()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(new_binary, perms).map_err(|e| CliError::Io(e.to_string()))?;
    }

    // Rename current binary to .old (backup)
    if target.exists() {
        fs::rename(&target, &backup_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                CliError::PermissionDenied(target_path.to_string())
            } else {
                CliError::Io(format!("Failed to backup current binary: {}", e))
            }
        })?;
    }

    // Move new binary to target location
    let move_result = fs::rename(new_binary, &target);

    if let Err(e) = move_result {
        // Restore backup on failure
        if backup_path.exists() {
            let _ = fs::rename(&backup_path, &target);
        }
        return Err(if e.kind() == std::io::ErrorKind::PermissionDenied {
            CliError::PermissionDenied(target_path.to_string())
        } else {
            CliError::Io(format!("Failed to install new binary: {}", e))
        });
    }

    // Remove backup on success
    if backup_path.exists() {
        let _ = fs::remove_file(&backup_path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version_parses() {
        let version = env!("CARGO_PKG_VERSION");
        let parsed = Version::parse(version);
        assert!(parsed.is_ok(), "Current version should be valid semver");
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("0.1.0").unwrap();
        let v2 = Version::parse("0.2.0").unwrap();
        let v3 = Version::parse("0.1.1").unwrap();

        assert!(v2 > v1);
        assert!(v3 > v1);
        assert!(v2 > v3);
    }

    #[test]
    fn test_checksum_format() {
        // SHA-256 should be 64 hex characters
        let valid_checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(valid_checksum.len(), 64);
        assert!(valid_checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
