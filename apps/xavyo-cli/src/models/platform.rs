//! Platform detection for the upgrade command

use std::env::consts::{ARCH, OS};

/// Represents the current system's OS and architecture
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// Operating system (linux, macos, windows)
    pub os: String,

    /// Architecture (`x86_64`, aarch64, arm64)
    pub arch: String,

    /// Corresponding asset name suffix
    pub asset_suffix: String,
}

impl Platform {
    /// Detect the current platform
    pub fn current() -> Self {
        let (os, arch, asset_suffix) = match (OS, ARCH) {
            ("linux", "x86_64") => ("linux", "x86_64", "linux-x86_64"),
            ("linux", "aarch64") => ("linux", "aarch64", "linux-aarch64"),
            ("macos", "x86_64") => ("macos", "x86_64", "darwin-x86_64"),
            ("macos", "aarch64") => ("macos", "arm64", "darwin-arm64"),
            ("windows", "x86_64") => ("windows", "x86_64", "windows-x86_64.exe"),
            (os, arch) => (os, arch, &format!("{os}-{arch}")[..]),
        };

        Platform {
            os: os.to_string(),
            arch: arch.to_string(),
            asset_suffix: asset_suffix.to_string(),
        }
    }

    /// Get the expected asset name for a given version
    pub fn asset_name(&self, version: &str) -> String {
        format!("xavyo-{}-{}", version, self.asset_suffix)
    }

    /// Check if this platform is supported
    pub fn is_supported(&self) -> bool {
        matches!(
            (self.os.as_str(), self.arch.as_str()),
            ("linux" | "macos" | "windows", "x86_64") | ("linux", "aarch64") |
("macos", "arm64")
        )
    }
}

/// Detected package manager installation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageManager {
    /// Installed via Homebrew
    Homebrew,
    /// Installed via Cargo
    Cargo,
    /// Installed via Nix
    Nix,
    /// Installed via system package manager (apt, dnf, etc.)
    System,
    /// Manual installation (direct download)
    Manual,
}

impl PackageManager {
    /// Detect how the CLI was installed based on the binary path
    pub fn detect(binary_path: &str) -> Self {
        if binary_path.contains("/usr/local/Cellar/")
            || binary_path.contains("/opt/homebrew/Cellar/")
            || binary_path.contains("/home/linuxbrew/")
        {
            PackageManager::Homebrew
        } else if binary_path.contains("/.cargo/bin/") {
            PackageManager::Cargo
        } else if binary_path.contains("/nix/store/") {
            PackageManager::Nix
        } else if binary_path.starts_with("/usr/bin/")
            || binary_path.starts_with("/usr/sbin/")
            || binary_path.contains("/apt/")
            || binary_path.contains("/dpkg/")
        {
            PackageManager::System
        } else {
            PackageManager::Manual
        }
    }

    /// Get the recommended upgrade command for this package manager
    pub fn upgrade_command(&self) -> Option<&'static str> {
        match self {
            PackageManager::Homebrew => Some("brew upgrade xavyo"),
            PackageManager::Cargo => Some("cargo install xavyo-cli --force"),
            PackageManager::Nix => Some("nix-env -u xavyo"),
            PackageManager::System => {
                Some("Use your system package manager (apt, dnf, pacman, etc.)")
            }
            PackageManager::Manual => None,
        }
    }

    /// Check if self-upgrade should be blocked by default
    pub fn blocks_self_upgrade(&self) -> bool {
        !matches!(self, PackageManager::Manual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_current_is_supported() {
        let platform = Platform::current();
        // Current platform should generally be supported on dev machines
        // This test just ensures detection doesn't panic
        let _ = platform.is_supported();
    }

    #[test]
    fn test_asset_name_generation() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            asset_suffix: "linux-x86_64".to_string(),
        };

        assert_eq!(platform.asset_name("0.2.0"), "xavyo-0.2.0-linux-x86_64");
    }

    #[test]
    fn test_package_manager_detection() {
        assert_eq!(
            PackageManager::detect("/usr/local/Cellar/xavyo/0.1.0/bin/xavyo"),
            PackageManager::Homebrew
        );
        assert_eq!(
            PackageManager::detect("/opt/homebrew/Cellar/xavyo/0.1.0/bin/xavyo"),
            PackageManager::Homebrew
        );
        assert_eq!(
            PackageManager::detect("/home/user/.cargo/bin/xavyo"),
            PackageManager::Cargo
        );
        assert_eq!(
            PackageManager::detect("/nix/store/abc123-xavyo/bin/xavyo"),
            PackageManager::Nix
        );
        assert_eq!(
            PackageManager::detect("/usr/bin/xavyo"),
            PackageManager::System
        );
        assert_eq!(
            PackageManager::detect("/usr/local/bin/xavyo"),
            PackageManager::Manual
        );
        assert_eq!(
            PackageManager::detect("/home/user/.local/bin/xavyo"),
            PackageManager::Manual
        );
    }

    #[test]
    fn test_package_manager_upgrade_command() {
        assert_eq!(
            PackageManager::Homebrew.upgrade_command(),
            Some("brew upgrade xavyo")
        );
        assert_eq!(
            PackageManager::Cargo.upgrade_command(),
            Some("cargo install xavyo-cli --force")
        );
        assert_eq!(PackageManager::Manual.upgrade_command(), None);
    }

    #[test]
    fn test_package_manager_blocks_self_upgrade() {
        assert!(PackageManager::Homebrew.blocks_self_upgrade());
        assert!(PackageManager::Cargo.blocks_self_upgrade());
        assert!(PackageManager::Nix.blocks_self_upgrade());
        assert!(PackageManager::System.blocks_self_upgrade());
        assert!(!PackageManager::Manual.blocks_self_upgrade());
    }
}
