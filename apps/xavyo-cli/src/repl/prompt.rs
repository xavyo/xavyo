//! Dynamic prompt generation for the interactive shell
//!
//! Generates context-aware prompts showing the current tenant
//! and authentication status.

use std::io::IsTerminal;

use crate::repl::ShellSession;

/// Prompt generator for the interactive shell
pub struct Prompt;

impl Prompt {
    /// Generate the prompt string based on current session state
    ///
    /// Format: `xavyo [tenant-name]> ` or `xavyo (not logged in)> `
    pub fn generate(session: &ShellSession) -> String {
        let context = session.prompt_context();
        let offline_suffix = if session.is_offline { " (offline)" } else { "" };

        format!("xavyo [{}]{offline_suffix}> ", context)
    }

    /// Generate a colored prompt for terminals that support ANSI colors
    pub fn generate_colored(session: &ShellSession) -> String {
        let context = session.prompt_context();
        let offline_suffix = if session.is_offline {
            "\x1b[33m (offline)\x1b[0m"
        } else {
            ""
        };

        // Use cyan for the context, green for xavyo
        format!(
            "\x1b[32mxavyo\x1b[0m [\x1b[36m{}\x1b[0m]{offline_suffix}> ",
            context
        )
    }

    /// Check if the terminal supports colors
    pub fn supports_color() -> bool {
        std::env::var("NO_COLOR").is_err() && std::io::stdout().is_terminal()
    }

    /// Generate the appropriate prompt based on terminal capabilities
    pub fn generate_auto(session: &ShellSession) -> String {
        if Self::supports_color() {
            Self::generate_colored(session)
        } else {
            Self::generate(session)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigPaths;
    use tempfile::TempDir;

    fn create_test_session() -> (TempDir, ShellSession) {
        let temp_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp_dir.path().to_path_buf(),
            config_file: temp_dir.path().join("config.json"),
            session_file: temp_dir.path().join("session.json"),
            credentials_file: temp_dir.path().join("credentials.enc"),
            cache_dir: temp_dir.path().join("cache"),
            history_file: temp_dir.path().join("history"),
        };
        let session = ShellSession::new(paths).unwrap();
        (temp_dir, session)
    }

    #[test]
    fn test_prompt_generate_unauthenticated() {
        let (_temp_dir, session) = create_test_session();
        let prompt = Prompt::generate(&session);
        assert_eq!(prompt, "xavyo [(not logged in)]> ");
    }

    #[test]
    fn test_prompt_generate_authenticated_no_tenant() {
        let (_temp_dir, mut session) = create_test_session();
        session.is_authenticated = true;
        let prompt = Prompt::generate(&session);
        assert_eq!(prompt, "xavyo [(no tenant)]> ");
    }

    #[test]
    fn test_prompt_generate_with_tenant() {
        let (_temp_dir, mut session) = create_test_session();
        session.is_authenticated = true;
        session.tenant_name = Some("my-tenant".to_string());
        let prompt = Prompt::generate(&session);
        assert_eq!(prompt, "xavyo [my-tenant]> ");
    }

    #[test]
    fn test_prompt_generate_offline() {
        let (_temp_dir, mut session) = create_test_session();
        session.is_authenticated = true;
        session.tenant_name = Some("my-tenant".to_string());
        session.is_offline = true;
        let prompt = Prompt::generate(&session);
        assert_eq!(prompt, "xavyo [my-tenant] (offline)> ");
    }

    #[test]
    fn test_prompt_colored_contains_ansi() {
        let (_temp_dir, session) = create_test_session();
        let prompt = Prompt::generate_colored(&session);
        // Should contain ANSI escape codes
        assert!(prompt.contains("\x1b["));
    }
}
