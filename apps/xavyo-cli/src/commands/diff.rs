//! Diff command for comparing YAML configurations
//!
//! This command provides functionality to compare two configuration files
//! or compare a local configuration with the remote server state.
//!
//! # Usage
//!
//! Compare two local files:
//! ```bash
//! xavyo diff config-staging.yaml config-prod.yaml
//! ```
//!
//! Compare local file with remote state:
//! ```bash
//! xavyo diff config.yaml --remote
//! ```
//!
//! Output as JSON for CI/CD:
//! ```bash
//! xavyo diff config.yaml --remote --output json
//! ```

use std::io::IsTerminal;

use crate::api::ApiClient;
use crate::commands::apply::{fetch_current_state, load_config};
use crate::config::{Config, ConfigPaths};
use crate::diff::{compare_configs, format_diff, DiffResult, OutputFormat};
use crate::error::{CliError, CliResult};
use crate::models::config::XavyoConfig;
use crate::verbose;
use clap::{Args, ValueEnum};
use std::path::PathBuf;

/// Output format options for the diff command
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum DiffOutputFormat {
    /// Display as formatted table (default)
    #[default]
    Table,
    /// Output as JSON
    Json,
    /// Output as YAML
    Yaml,
}

impl From<DiffOutputFormat> for OutputFormat {
    fn from(format: DiffOutputFormat) -> Self {
        match format {
            DiffOutputFormat::Table => OutputFormat::Table,
            DiffOutputFormat::Json => OutputFormat::Json,
            DiffOutputFormat::Yaml => OutputFormat::Yaml,
        }
    }
}

/// Compare YAML configurations
///
/// Compare two local config files, or compare a local config with the current
/// remote state. Useful for previewing changes before applying or detecting
/// configuration drift.
///
/// # Examples
///
///   Compare two local files:
///     xavyo diff config-staging.yaml config-prod.yaml
///
///   Compare local file with remote state:
///     xavyo diff config.yaml --remote
///
///   Output as JSON for CI/CD:
///     xavyo diff config.yaml --remote --output json
#[derive(Args, Debug)]
#[command(after_help = "EXIT CODES:
    0  No differences found (configurations match)
    1  Differences detected
    2  Error occurred (file not found, parse error, auth error)

EXAMPLES:
    # Compare two local config files
    xavyo diff staging.yaml production.yaml

    # Compare local config with remote state
    xavyo diff config.yaml --remote

    # Output as JSON for CI/CD pipelines
    xavyo diff config.yaml --remote --output json

    # Output as YAML
    xavyo diff file1.yaml file2.yaml --output yaml

    # Disable colored output for logging
    xavyo diff file1.yaml file2.yaml --no-color
")]
pub struct DiffArgs {
    /// First configuration file
    #[arg(value_name = "FILE1")]
    pub file1: PathBuf,

    /// Second configuration file (optional if --remote is used)
    #[arg(value_name = "FILE2")]
    pub file2: Option<PathBuf>,

    /// Compare FILE1 with current remote state instead of FILE2
    #[arg(short = 'r', long)]
    pub remote: bool,

    /// Output format
    #[arg(short = 'o', long, value_enum, default_value = "table")]
    pub output: DiffOutputFormat,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
}

/// Mode of diff operation
#[derive(Debug, Clone)]
enum DiffMode {
    /// Comparing two local files
    TwoFiles { file1: PathBuf, file2: PathBuf },
    /// Comparing local file with remote state
    LocalVsRemote { local_file: PathBuf },
}

/// Execute the diff command
pub async fn execute(args: DiffArgs) -> CliResult<()> {
    // Determine diff mode
    let mode = determine_mode(&args)?;

    // Determine if we should use color
    let use_color = should_use_color(args.no_color);

    // Execute the appropriate diff operation
    let result = match mode {
        DiffMode::TwoFiles { file1, file2 } => diff_two_files(&file1, &file2).await?,
        DiffMode::LocalVsRemote { local_file } => diff_local_vs_remote(&local_file).await?,
    };

    // Format and print the result
    let output = format_diff(&result, args.output.into(), use_color);
    print!("{}", output);

    // Return appropriate exit code
    // Note: The actual exit is handled by main.rs based on the result
    // We return an error with a special code if changes are detected
    if result.has_changes() {
        std::process::exit(result.exit_code());
    }

    Ok(())
}

/// Determine the diff mode from command arguments
fn determine_mode(args: &DiffArgs) -> CliResult<DiffMode> {
    if args.remote {
        // Remote mode - comparing local file with server state
        if args.file2.is_some() {
            return Err(CliError::Validation(
                "Cannot specify FILE2 when using --remote flag".to_string(),
            ));
        }
        Ok(DiffMode::LocalVsRemote {
            local_file: args.file1.clone(),
        })
    } else {
        // Two-file mode
        let file2 = args.file2.clone().ok_or_else(|| {
            CliError::Validation(
                "FILE2 is required when not using --remote flag. \
                 Usage: xavyo diff <FILE1> <FILE2> or xavyo diff <FILE1> --remote"
                    .to_string(),
            )
        })?;
        Ok(DiffMode::TwoFiles {
            file1: args.file1.clone(),
            file2,
        })
    }
}

/// Check if we should use colored output
fn should_use_color(no_color_flag: bool) -> bool {
    if no_color_flag {
        return false;
    }

    // Check NO_COLOR environment variable (standard convention)
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }

    // Check if stdout is a TTY
    std::io::stdout().is_terminal()
}

/// Compare two local configuration files
async fn diff_two_files(file1: &PathBuf, file2: &PathBuf) -> CliResult<DiffResult> {
    verbose!("Loading config: {}", file1.display());
    let config1 = load_and_parse_yaml(file1)?;

    verbose!("Loading config: {}", file2.display());
    let config2 = load_and_parse_yaml(file2)?;

    verbose!(
        "Comparing {} agents, {} tools from source",
        config1.agents.len(),
        config1.tools.len()
    );
    verbose!(
        "Comparing {} agents, {} tools from target",
        config2.agents.len(),
        config2.tools.len()
    );

    let result = compare_configs(
        &config1,
        &config2,
        file1.display().to_string(),
        file2.display().to_string(),
    );

    Ok(result)
}

/// Compare a local configuration file with the remote server state
async fn diff_local_vs_remote(local_file: &PathBuf) -> CliResult<DiffResult> {
    verbose!("Loading local config: {}", local_file.display());
    let local_config = load_and_parse_yaml(local_file)?;

    verbose!("Fetching remote state...");
    let remote_config = fetch_remote_config().await?;

    verbose!(
        "Comparing {} local agents, {} local tools",
        local_config.agents.len(),
        local_config.tools.len()
    );
    verbose!(
        "Against {} remote agents, {} remote tools",
        remote_config.agents.len(),
        remote_config.tools.len()
    );

    // Note: For remote comparison, we compare local -> remote
    // so "added" means resources in local that aren't in remote (will be created)
    // and "removed" means resources in remote that aren't in local (won't be in config)
    let result = compare_configs(
        &remote_config,
        &local_config,
        "remote",
        local_file.display().to_string(),
    );

    Ok(result)
}

/// Load and parse a YAML configuration file
fn load_and_parse_yaml(path: &PathBuf) -> CliResult<XavyoConfig> {
    if !path.exists() {
        return Err(CliError::Validation(format!(
            "File not found: {}",
            path.display()
        )));
    }

    load_config(path)
}

/// Fetch the current remote configuration state
async fn fetch_remote_config() -> CliResult<XavyoConfig> {
    // Set up API client
    let paths = ConfigPaths::new()?;
    let cli_config = Config::load(&paths).map_err(|e| {
        CliError::AuthenticationFailed(format!(
            "Not authenticated. Run 'xavyo login' to authenticate. Error: {}",
            e
        ))
    })?;

    let client = ApiClient::new(cli_config, paths).map_err(|e| {
        CliError::AuthenticationFailed(format!(
            "Not authenticated. Run 'xavyo login' to authenticate. Error: {}",
            e
        ))
    })?;

    // Fetch current state from API
    let (current_agents, current_tools) = fetch_current_state(&client).await?;

    // Convert API responses to XavyoConfig format
    let agents = current_agents
        .into_iter()
        .map(|a| crate::models::config::AgentConfig {
            name: a.name,
            agent_type: a.agent_type,
            model_provider: a.model_provider.unwrap_or_default(),
            model_name: a.model_name.unwrap_or_default(),
            risk_level: a.risk_level,
            description: a.description,
            tools: vec![], // Tool assignments fetched separately if needed
        })
        .collect();

    let tools = current_tools
        .into_iter()
        .map(|t| crate::models::config::ToolConfig {
            name: t.name,
            description: t.description.unwrap_or_default(),
            risk_level: t.risk_level,
            input_schema: t.input_schema,
        })
        .collect();

    Ok(XavyoConfig {
        version: "1".to_string(),
        agents,
        tools,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_mode_two_files() {
        let args = DiffArgs {
            file1: PathBuf::from("file1.yaml"),
            file2: Some(PathBuf::from("file2.yaml")),
            remote: false,
            output: DiffOutputFormat::Table,
            no_color: false,
        };

        let mode = determine_mode(&args).unwrap();
        matches!(mode, DiffMode::TwoFiles { .. });
    }

    #[test]
    fn test_determine_mode_remote() {
        let args = DiffArgs {
            file1: PathBuf::from("config.yaml"),
            file2: None,
            remote: true,
            output: DiffOutputFormat::Table,
            no_color: false,
        };

        let mode = determine_mode(&args).unwrap();
        matches!(mode, DiffMode::LocalVsRemote { .. });
    }

    #[test]
    fn test_determine_mode_error_remote_with_file2() {
        let args = DiffArgs {
            file1: PathBuf::from("file1.yaml"),
            file2: Some(PathBuf::from("file2.yaml")),
            remote: true,
            output: DiffOutputFormat::Table,
            no_color: false,
        };

        let result = determine_mode(&args);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot specify FILE2"));
    }

    #[test]
    fn test_determine_mode_error_missing_file2() {
        let args = DiffArgs {
            file1: PathBuf::from("file1.yaml"),
            file2: None,
            remote: false,
            output: DiffOutputFormat::Table,
            no_color: false,
        };

        let result = determine_mode(&args);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("FILE2 is required"));
    }

    #[test]
    fn test_should_use_color() {
        // no_color flag takes precedence
        assert!(!should_use_color(true));
    }

    #[test]
    fn test_diff_output_format_conversion() {
        assert_eq!(
            OutputFormat::from(DiffOutputFormat::Table),
            OutputFormat::Table
        );
        assert_eq!(
            OutputFormat::from(DiffOutputFormat::Json),
            OutputFormat::Json
        );
        assert_eq!(
            OutputFormat::from(DiffOutputFormat::Yaml),
            OutputFormat::Yaml
        );
    }
}
