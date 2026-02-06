//! Plugin scaffolding
//!
//! Provides functionality to create new plugin project templates.

use crate::error::{CliError, CliResult};
use std::path::Path;

/// Create a new plugin project scaffold
pub fn create_plugin_scaffold(name: &str, dest_dir: &Path) -> CliResult<()> {
    // Validate plugin name
    if !is_valid_plugin_name(name) {
        return Err(CliError::PluginInvalid {
            name: name.to_string(),
            reason: "Plugin name must be lowercase alphanumeric with hyphens, 2-50 characters"
                .to_string(),
        });
    }

    // Create directory structure
    let plugin_dir = dest_dir.join(name);
    let bin_dir = plugin_dir.join("bin");
    let src_dir = plugin_dir.join("src");

    std::fs::create_dir_all(&bin_dir).map_err(|e| {
        CliError::Io(format!(
            "Failed to create bin directory {}: {}",
            bin_dir.display(),
            e
        ))
    })?;

    std::fs::create_dir_all(&src_dir).map_err(|e| {
        CliError::Io(format!(
            "Failed to create src directory {}: {}",
            src_dir.display(),
            e
        ))
    })?;

    // Create plugin.toml
    let manifest_content = format!(
        r#"[plugin]
name = "{name}"
version = "0.1.0"
description = "Description of {name}"
author = "Your Name"
min_cli_version = "0.1.0"
license = "MIT"

[[commands]]
name = "{name}"
description = "Run the {name} command"
binary = "{name}"
"#
    );

    std::fs::write(plugin_dir.join("plugin.toml"), manifest_content)
        .map_err(|e| CliError::Io(format!("Failed to write plugin.toml: {}", e)))?;

    // Create Cargo.toml for Rust plugins
    let cargo_content = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "{name}"
path = "src/main.rs"

[dependencies]
clap = {{ version = "4", features = ["derive"] }}
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"
"#
    );

    std::fs::write(plugin_dir.join("Cargo.toml"), cargo_content)
        .map_err(|e| CliError::Io(format!("Failed to write Cargo.toml: {}", e)))?;

    // Create src/main.rs
    let main_content = format!(
        r#"//! {name} plugin for xavyo-cli

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "{name}")]
#[command(about = "Description of {name}")]
struct Args {{
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Input file (optional)
    input: Option<String>,
}}

fn main() {{
    let args = Args::parse();

    if args.verbose {{
        eprintln!("Running {name} in verbose mode");
    }}

    if let Some(input) = args.input {{
        println!("Processing: {{}}", input);
    }} else {{
        println!("Hello from {name} plugin!");
    }}
}}
"#
    );

    std::fs::write(src_dir.join("main.rs"), main_content)
        .map_err(|e| CliError::Io(format!("Failed to write main.rs: {}", e)))?;

    // Create README.md
    let readme_content = format!(
        r#"# {name}

A plugin for xavyo-cli.

## Installation

```bash
# Build the plugin
cargo build --release

# Copy the binary to bin/
cp target/release/{name} bin/

# Install the plugin
xavyo plugin install --path .
```

## Usage

```bash
xavyo {name} [OPTIONS] [INPUT]
```

## Development

```bash
# Build
cargo build

# Run locally
cargo run -- --help
```
"#
    );

    std::fs::write(plugin_dir.join("README.md"), readme_content)
        .map_err(|e| CliError::Io(format!("Failed to write README.md: {}", e)))?;

    // Create .gitignore
    let gitignore_content = r#"/target/
Cargo.lock
"#;

    std::fs::write(plugin_dir.join(".gitignore"), gitignore_content)
        .map_err(|e| CliError::Io(format!("Failed to write .gitignore: {}", e)))?;

    Ok(())
}

/// Check if a plugin name is valid
fn is_valid_plugin_name(name: &str) -> bool {
    if name.len() < 2 || name.len() > 50 {
        return false;
    }

    let chars: Vec<char> = name.chars().collect();

    // Must start with a letter
    if !chars[0].is_ascii_lowercase() {
        return false;
    }

    // Must end with a letter or digit
    if !chars[chars.len() - 1].is_ascii_alphanumeric() {
        return false;
    }

    // All characters must be lowercase alphanumeric or hyphen
    chars
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_scaffold() {
        let temp = TempDir::new().unwrap();
        create_plugin_scaffold("my-test-plugin", temp.path()).unwrap();

        let plugin_dir = temp.path().join("my-test-plugin");
        assert!(plugin_dir.exists());
        assert!(plugin_dir.join("plugin.toml").exists());
        assert!(plugin_dir.join("Cargo.toml").exists());
        assert!(plugin_dir.join("src/main.rs").exists());
        assert!(plugin_dir.join("bin").exists());
        assert!(plugin_dir.join("README.md").exists());
        assert!(plugin_dir.join(".gitignore").exists());
    }

    #[test]
    fn test_invalid_plugin_name() {
        let temp = TempDir::new().unwrap();
        let result = create_plugin_scaffold("InvalidName", temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_plugin_names() {
        assert!(is_valid_plugin_name("ab"));
        assert!(is_valid_plugin_name("my-plugin"));
        assert!(is_valid_plugin_name("plugin123"));

        assert!(!is_valid_plugin_name("a"));
        assert!(!is_valid_plugin_name("Invalid"));
        assert!(!is_valid_plugin_name("-bad"));
    }
}
