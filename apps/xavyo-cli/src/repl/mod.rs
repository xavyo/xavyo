//! Interactive REPL (Read-Eval-Print-Loop) module for the xavyo CLI
//!
//! This module provides an interactive shell experience for executing
//! multiple commands in sequence with tab completion, command history,
//! and a context-aware prompt.

mod completer;
mod executor;
mod prompt;
mod session;

pub use completer::Completer;
pub use executor::{CommandExecutor, ExecuteResult};
pub use prompt::Prompt;
pub use session::ShellSession;
