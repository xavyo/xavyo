//! Tab completion for the interactive shell
//!
//! Provides context-aware tab completion for commands, subcommands,
//! and flags based on the CLI command structure.

use clap::Command;
use rustyline::completion::{Candidate, Completer as RustylineCompleter};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper, Result};
use std::borrow::Cow;
use std::collections::HashMap;

/// Completion candidate
#[derive(Debug)]
pub struct CompletionCandidate {
    display: String,
    replacement: String,
}

impl Candidate for CompletionCandidate {
    fn display(&self) -> &str {
        &self.display
    }

    fn replacement(&self) -> &str {
        &self.replacement
    }
}

/// Node in the completion tree
#[derive(Debug, Default, Clone)]
struct CommandNode {
    /// Available subcommands
    subcommands: Vec<String>,
    /// Available flags (--flag)
    flags: Vec<String>,
    /// Available short flags (-f)
    short_flags: Vec<String>,
    /// Nested subcommand nodes
    children: HashMap<String, CommandNode>,
}

/// Tab completion for the interactive shell
pub struct Completer {
    /// Root completion tree
    root: CommandNode,
}

impl Completer {
    /// Create a new completer from a clap Command
    pub fn new(command: Command) -> Self {
        let root = Self::build_tree(&command);
        Self { root }
    }

    /// Build the completion tree from a clap Command
    fn build_tree(command: &Command) -> CommandNode {
        let mut node = CommandNode::default();

        // Add subcommands
        for subcmd in command.get_subcommands() {
            let name = subcmd.get_name().to_string();
            node.subcommands.push(name.clone());

            // Recursively build child nodes
            let child_node = Self::build_tree(subcmd);
            node.children.insert(name, child_node);
        }

        // Add flags
        for arg in command.get_arguments() {
            if let Some(long) = arg.get_long() {
                node.flags.push(format!("--{}", long));
            }
            if let Some(short) = arg.get_short() {
                node.short_flags.push(format!("-{}", short));
            }
        }

        node
    }

    /// Get completions for a partial command line
    fn get_completions(&self, line: &str, pos: usize) -> Vec<CompletionCandidate> {
        let line = &line[..pos];
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Determine what we're completing
        let (node, prefix) = self.find_context(&parts, line);

        let mut candidates = Vec::new();

        // Check if completing a flag
        if let Some(partial) = prefix.strip_prefix("--") {
            // Complete long flags
            for flag in &node.flags {
                if let Some(flag_name) = flag.strip_prefix("--") {
                    if flag_name.starts_with(partial) {
                        candidates.push(CompletionCandidate {
                            display: flag.clone(),
                            replacement: flag.clone(),
                        });
                    }
                }
            }
        } else if let Some(partial) = prefix.strip_prefix('-') {
            // Complete short flags
            for flag in &node.short_flags {
                if let Some(flag_name) = flag.strip_prefix('-') {
                    if flag_name.starts_with(partial) {
                        candidates.push(CompletionCandidate {
                            display: flag.clone(),
                            replacement: flag.clone(),
                        });
                    }
                }
            }
            // Also show long flags
            for flag in &node.flags {
                candidates.push(CompletionCandidate {
                    display: flag.clone(),
                    replacement: flag.clone(),
                });
            }
        } else {
            // Complete commands/subcommands
            for subcmd in &node.subcommands {
                if subcmd.starts_with(prefix) {
                    candidates.push(CompletionCandidate {
                        display: subcmd.clone(),
                        replacement: subcmd.clone(),
                    });
                }
            }
        }

        candidates
    }

    /// Find the context node and current prefix for completion
    fn find_context<'a>(&'a self, parts: &[&'a str], line: &'a str) -> (&'a CommandNode, &'a str) {
        let mut node = &self.root;

        // Navigate through known commands
        let mut i = 0;
        while i < parts.len() {
            let part = parts[i];

            // Skip flags
            if part.starts_with('-') {
                i += 1;
                // Skip flag value if it looks like the flag takes a value
                if i < parts.len() && !parts[i].starts_with('-') {
                    i += 1;
                }
                continue;
            }

            // Try to descend into subcommand
            if let Some(child) = node.children.get(part) {
                node = child;
                i += 1;
            } else {
                break;
            }
        }

        // Determine the prefix being completed
        let prefix = if line.ends_with(' ') {
            ""
        } else if let Some(last_word) = parts.last() {
            if node.subcommands.contains(&last_word.to_string()) {
                // We're starting a new word after a complete command
                ""
            } else {
                last_word
            }
        } else {
            ""
        };

        (node, prefix)
    }
}

impl RustylineCompleter for Completer {
    type Candidate = CompletionCandidate;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Self::Candidate>)> {
        let candidates = self.get_completions(line, pos);

        // Calculate the start position for replacement
        let start = if let Some(last_space) = line[..pos].rfind(char::is_whitespace) {
            last_space + 1
        } else {
            0
        };

        Ok((start, candidates))
    }
}

impl Hinter for Completer {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        // No inline hints for now
        None
    }
}

impl Highlighter for Completer {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        Cow::Borrowed(prompt)
    }
}

impl Validator for Completer {}

impl Helper for Completer {}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_command() -> Command {
        Command::new("xavyo")
            .subcommand(
                Command::new("agents")
                    .about("Manage AI agents")
                    .subcommand(Command::new("list").about("List agents"))
                    .subcommand(Command::new("get").about("Get an agent"))
                    .subcommand(Command::new("create").about("Create an agent"))
                    .arg(clap::Arg::new("json").long("json").short('j')),
            )
            .subcommand(
                Command::new("tools")
                    .about("Manage tools")
                    .subcommand(Command::new("list").about("List tools")),
            )
            .subcommand(Command::new("login").about("Authenticate"))
            .subcommand(Command::new("logout").about("Clear credentials"))
    }

    #[test]
    fn test_completion_tree_building() {
        let cmd = create_test_command();
        let completer = Completer::new(cmd);

        // Root should have subcommands
        assert!(completer.root.subcommands.contains(&"agents".to_string()));
        assert!(completer.root.subcommands.contains(&"tools".to_string()));
        assert!(completer.root.subcommands.contains(&"login".to_string()));
    }

    #[test]
    fn test_command_completion_empty() {
        let cmd = create_test_command();
        let completer = Completer::new(cmd);

        let completions = completer.get_completions("", 0);
        assert!(!completions.is_empty());

        let names: Vec<_> = completions.iter().map(|c| c.display.as_str()).collect();
        assert!(names.contains(&"agents"));
        assert!(names.contains(&"tools"));
    }

    #[test]
    fn test_command_completion_partial() {
        let cmd = create_test_command();
        let completer = Completer::new(cmd);

        let completions = completer.get_completions("ag", 2);
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].display, "agents");
    }

    #[test]
    fn test_subcommand_completion() {
        let cmd = create_test_command();
        let completer = Completer::new(cmd);

        let completions = completer.get_completions("agents ", 7);
        let names: Vec<_> = completions.iter().map(|c| c.display.as_str()).collect();
        assert!(names.contains(&"list"));
        assert!(names.contains(&"get"));
        assert!(names.contains(&"create"));
    }

    #[test]
    fn test_flag_completion() {
        let cmd = create_test_command();
        let completer = Completer::new(cmd);

        let completions = completer.get_completions("agents --", 9);
        let names: Vec<_> = completions.iter().map(|c| c.display.as_str()).collect();
        assert!(names.contains(&"--json"));
    }
}
