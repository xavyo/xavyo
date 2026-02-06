//! Scope definitions for interactive API key creation.
//!
//! Provides scope options with human-readable descriptions for
//! the interactive API key creation workflow.

/// Scope definition with human-readable description.
#[derive(Debug, Clone)]
pub struct ScopeOption {
    pub scope: &'static str,
    pub description: &'static str,
}

impl std::fmt::Display for ScopeOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<24} - {}", self.scope, self.description)
    }
}

/// Available NHI scopes for API key creation.
///
/// These scopes follow the `nhi:resource:action` pattern and control
/// what operations an API key can perform.
pub const NHI_SCOPES: &[ScopeOption] = &[
    ScopeOption {
        scope: "nhi:agents:read",
        description: "View agents and their details",
    },
    ScopeOption {
        scope: "nhi:agents:create",
        description: "Create new agents",
    },
    ScopeOption {
        scope: "nhi:agents:update",
        description: "Modify existing agents",
    },
    ScopeOption {
        scope: "nhi:agents:delete",
        description: "Delete agents",
    },
    ScopeOption {
        scope: "nhi:agents:*",
        description: "Full agent access",
    },
    ScopeOption {
        scope: "nhi:credentials:rotate",
        description: "Rotate agent credentials",
    },
    ScopeOption {
        scope: "nhi:credentials:*",
        description: "Full credential access",
    },
    ScopeOption {
        scope: "nhi:*",
        description: "Full NHI access (all operations)",
    },
];

/// Returns scope labels formatted for display in multi-select prompts.
pub fn scope_display_labels() -> Vec<String> {
    NHI_SCOPES.iter().map(|s| format!("{}", s)).collect()
}

/// Converts selected indices to scope strings.
pub fn indices_to_scopes(indices: &[usize]) -> Vec<String> {
    indices
        .iter()
        .filter_map(|&i| NHI_SCOPES.get(i).map(|s| s.scope.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_option_display() {
        let option = &NHI_SCOPES[0];
        let display = format!("{}", option);
        assert!(display.contains("nhi:agents:read"));
        assert!(display.contains("View agents"));
    }

    #[test]
    fn test_nhi_scopes_count() {
        assert_eq!(NHI_SCOPES.len(), 8);
    }

    #[test]
    fn test_scope_display_labels() {
        let labels = scope_display_labels();
        assert_eq!(labels.len(), NHI_SCOPES.len());
        assert!(labels[0].contains("nhi:agents:read"));
    }

    #[test]
    fn test_indices_to_scopes() {
        let indices = vec![0, 2, 4];
        let scopes = indices_to_scopes(&indices);
        assert_eq!(scopes.len(), 3);
        assert_eq!(scopes[0], "nhi:agents:read");
        assert_eq!(scopes[1], "nhi:agents:update");
        assert_eq!(scopes[2], "nhi:agents:*");
    }

    #[test]
    fn test_indices_to_scopes_empty() {
        let indices: Vec<usize> = vec![];
        let scopes = indices_to_scopes(&indices);
        assert!(scopes.is_empty());
    }

    #[test]
    fn test_scope_descriptions_are_nonempty() {
        for scope in NHI_SCOPES {
            assert!(!scope.scope.is_empty());
            assert!(!scope.description.is_empty());
        }
    }
}
