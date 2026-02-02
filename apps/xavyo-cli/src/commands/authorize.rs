//! Authorization testing CLI command

use crate::api::ApiClient;
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::authorize::{AuthorizationContext, AuthorizeRequest, AuthorizeResponse};
use clap::Args;
use uuid::Uuid;

/// Arguments for the authorize command
#[derive(Args, Debug)]
pub struct AuthorizeArgs {
    /// Agent ID (UUID)
    #[arg(long, short = 'a')]
    pub agent: String,

    /// Tool name
    #[arg(long, short = 't')]
    pub tool: String,

    /// Tool parameters as JSON
    #[arg(long, short = 'p')]
    pub params: Option<String>,

    /// Authorization context as JSON
    #[arg(long, short = 'c')]
    pub context: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Execute authorize command
pub async fn execute(args: AuthorizeArgs) -> CliResult<()> {
    // Validate agent ID
    let agent_id = parse_agent_id(&args.agent)?;

    // Parse optional parameters
    let parameters = match args.params {
        Some(ref p) => Some(parse_json(p, "--params")?),
        None => None,
    };

    // Parse optional context
    let context = match args.context {
        Some(ref c) => Some(parse_context(c)?),
        None => None,
    };

    // Build request
    let request = AuthorizeRequest::new(agent_id, args.tool.clone())
        .with_parameters(parameters)
        .with_context(context);

    // Execute API call
    let paths = ConfigPaths::new()?;
    let config = Config::load(&paths)?;
    let client = ApiClient::new(config, paths)?;

    let response = client.authorize(request).await?;

    // Output result
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        print_authorization_result(&args.agent, &args.tool, &response);
    }

    Ok(())
}

/// Parse agent ID from string
fn parse_agent_id(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid agent ID '{}'. Must be a valid UUID.",
            id_str
        ))
    })
}

/// Parse JSON string
fn parse_json(json_str: &str, flag_name: &str) -> CliResult<serde_json::Value> {
    serde_json::from_str(json_str)
        .map_err(|e| CliError::Validation(format!("Invalid JSON in {}: {}", flag_name, e)))
}

/// Parse authorization context from JSON string
fn parse_context(json_str: &str) -> CliResult<AuthorizationContext> {
    serde_json::from_str(json_str)
        .map_err(|e| CliError::Validation(format!("Invalid JSON in --context: {}", e)))
}

/// Print authorization result in human-readable format
fn print_authorization_result(agent: &str, tool: &str, response: &AuthorizeResponse) {
    println!();
    println!("Authorization Decision");
    println!("{}", "━".repeat(45));
    println!("Agent:       {}", agent);
    println!("Tool:        {}", tool);

    // Decision with indicator
    let (indicator, decision_display) = match response.decision.as_str() {
        "allow" => ("✓", "ALLOW"),
        "deny" => ("✗", "DENY"),
        "require_approval" => ("⏳", "REQUIRE_APPROVAL"),
        _ => ("?", response.decision.as_str()),
    };
    println!("Decision:    {} {}", indicator, decision_display);

    println!("Reason:      {}", response.reason);
    println!("Decision ID: {}", response.decision_id);

    // Show approval request ID if present
    if let Some(approval_id) = response.approval_request_id {
        println!("Approval ID: {}", approval_id);
    }

    println!("Latency:     {:.1}ms", response.latency_ms);
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_agent_id_valid() {
        let valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_agent_id(valid_uuid).is_ok());
    }

    #[test]
    fn test_parse_agent_id_invalid() {
        let invalid_uuid = "not-a-uuid";
        assert!(parse_agent_id(invalid_uuid).is_err());
    }

    #[test]
    fn test_parse_json_valid() {
        let json = r#"{"key": "value"}"#;
        let result = parse_json(json, "--params");
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["key"], "value");
    }

    #[test]
    fn test_parse_json_invalid() {
        let invalid = "not json";
        let result = parse_json(invalid, "--params");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_context_valid() {
        let json = r#"{"conversation_id": "conv-123", "session_id": "sess-456"}"#;
        let result = parse_context(json);
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.conversation_id.as_deref(), Some("conv-123"));
        assert_eq!(ctx.session_id.as_deref(), Some("sess-456"));
    }

    #[test]
    fn test_parse_context_invalid() {
        let invalid = "{invalid}";
        let result = parse_context(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_context_empty_object() {
        let json = "{}";
        let result = parse_context(json);
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert!(ctx.conversation_id.is_none());
        assert!(ctx.session_id.is_none());
    }
}
