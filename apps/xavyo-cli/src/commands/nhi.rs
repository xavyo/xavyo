//! Unified NHI management CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::nhi::{
    AutoSuspendResponse, CampaignResponse, CreateCampaignRequest, CreateSodRuleRequest,
    GracePeriodRequest, GrantPermissionRequest, InactiveEntity, IssueCredentialRequest,
    NhiCredentialResponse, NhiIdentityResponse, OrphanEntity, PermissionResponse, RiskFactor,
    RotateCredentialRequest, SodCheckRequest, SodRuleResponse, SuspendRequest,
};
use crate::output::truncate;
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// Unified NHI management commands
#[derive(Args, Debug)]
pub struct NhiArgs {
    #[command(subcommand)]
    pub command: NhiCommands,
}

#[derive(Subcommand, Debug)]
pub enum NhiCommands {
    /// List all NHI identities (agents, tools, service accounts)
    List(ListArgs),
    /// Get details of an NHI identity
    Get(GetArgs),

    // Lifecycle
    /// Suspend an NHI identity
    Suspend(SuspendArgs),
    /// Reactivate a suspended NHI identity
    Reactivate(IdJsonArgs),
    /// Deprecate an NHI identity
    Deprecate(IdJsonArgs),
    /// Archive an NHI identity
    Archive(IdJsonArgs),
    /// Deactivate an NHI identity
    Deactivate(IdJsonArgs),
    /// Activate an NHI identity
    Activate(IdJsonArgs),

    /// Manage NHI credentials
    #[command(subcommand)]
    Credentials(CredentialsCommands),

    /// Manage agent-tool permissions
    #[command(subcommand)]
    Permissions(PermissionsCommands),

    /// Get risk assessment for an NHI identity
    Risk(RiskArgs),
    /// Get tenant-wide risk summary
    RiskSummary(JsonOnlyArgs),

    /// Manage certification campaigns
    #[command(subcommand)]
    Certifications(CertificationsCommands),

    /// Manage Separation of Duties rules
    #[command(subcommand)]
    Sod(SodCommands),

    /// Manage inactivity detection
    #[command(subcommand)]
    Inactivity(InactivityCommands),

    /// Detect orphaned NHI identities
    #[command(subcommand)]
    Orphans(OrphansCommands),
}

// --- Shared arg structs ---

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Filter by type: agent, tool, service_account
    #[arg(long, short = 't')]
    pub r#type: Option<String>,
    /// Filter by lifecycle state: active, suspended, deprecated, archived, inactive
    #[arg(long, short = 's')]
    pub state: Option<String>,
    /// Filter by owner user ID
    #[arg(long)]
    pub owner: Option<String>,
    /// Maximum results to return
    #[arg(long, default_value = "50")]
    pub limit: i32,
    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: i32,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// NHI identity ID (UUID)
    pub id: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SuspendArgs {
    /// NHI identity ID (UUID)
    pub id: String,
    /// Reason for suspension
    #[arg(long)]
    pub reason: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct IdJsonArgs {
    /// NHI identity ID (UUID)
    pub id: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct JsonOnlyArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct RiskArgs {
    /// NHI identity ID (UUID)
    pub id: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// --- Credentials ---

#[derive(Subcommand, Debug)]
pub enum CredentialsCommands {
    /// Issue a new credential for an NHI identity
    Issue(CredIssueArgs),
    /// List credentials for an NHI identity
    List(CredListArgs),
    /// Rotate an existing credential
    Rotate(CredRotateArgs),
    /// Revoke (delete) a credential
    Revoke(CredRevokeArgs),
}

#[derive(Args, Debug)]
pub struct CredIssueArgs {
    /// NHI identity ID (UUID)
    pub nhi_id: String,
    /// Credential type: api_key, secret, certificate
    #[arg(long, short = 't')]
    pub r#type: String,
    /// Validity in days
    #[arg(long)]
    pub valid_days: Option<i32>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CredListArgs {
    /// NHI identity ID (UUID)
    pub nhi_id: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CredRotateArgs {
    /// NHI identity ID (UUID)
    pub nhi_id: String,
    /// Credential ID (UUID)
    pub credential_id: String,
    /// Grace period in hours before old credential expires
    #[arg(long)]
    pub grace_period_hours: Option<i32>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CredRevokeArgs {
    /// NHI identity ID (UUID)
    pub nhi_id: String,
    /// Credential ID (UUID)
    pub credential_id: String,
    /// Skip confirmation prompt
    #[arg(long, short = 'f')]
    pub force: bool,
}

// --- Permissions ---

#[derive(Subcommand, Debug)]
pub enum PermissionsCommands {
    /// Grant a tool permission to an agent
    Grant(PermGrantArgs),
    /// Revoke a tool permission from an agent
    Revoke(PermRevokeArgs),
    /// List tools an agent has permission to use
    ListTools(PermListToolsArgs),
    /// List agents that have permission to a tool
    ListAgents(PermListAgentsArgs),
}

#[derive(Args, Debug)]
pub struct PermGrantArgs {
    /// Agent NHI identity ID
    #[arg(long)]
    pub agent: String,
    /// Tool NHI identity ID
    #[arg(long)]
    pub tool: String,
    /// Permission expiration (ISO 8601 datetime)
    #[arg(long)]
    pub expires_at: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct PermRevokeArgs {
    /// Agent NHI identity ID
    #[arg(long)]
    pub agent: String,
    /// Tool NHI identity ID
    #[arg(long)]
    pub tool: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct PermListToolsArgs {
    /// Agent NHI identity ID
    #[arg(long)]
    pub agent: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct PermListAgentsArgs {
    /// Tool NHI identity ID
    #[arg(long)]
    pub tool: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// --- Certifications ---

#[derive(Subcommand, Debug)]
pub enum CertificationsCommands {
    /// Create a certification campaign
    Create(CertCreateArgs),
    /// List certification campaigns
    List(CertListArgs),
    /// Certify an NHI identity in a campaign
    Certify(CertActionArgs),
    /// Revoke certification for an NHI identity
    Revoke(CertActionArgs),
}

#[derive(Args, Debug)]
pub struct CertCreateArgs {
    /// Campaign name
    #[arg(long)]
    pub name: String,
    /// Campaign description
    #[arg(long, short = 'd')]
    pub description: Option<String>,
    /// Scope: all, by_type, specific
    #[arg(long)]
    pub scope: Option<String>,
    /// Due date (ISO 8601 date)
    #[arg(long)]
    pub due_date: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CertListArgs {
    /// Filter by status
    #[arg(long)]
    pub status: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CertActionArgs {
    /// Campaign ID (UUID)
    pub campaign_id: String,
    /// NHI identity ID (UUID)
    pub nhi_id: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// --- SoD ---

#[derive(Subcommand, Debug)]
pub enum SodCommands {
    /// Create a new SoD rule
    CreateRule(SodCreateRuleArgs),
    /// List all SoD rules
    ListRules(JsonOnlyArgs),
    /// Delete a SoD rule
    DeleteRule(SodDeleteRuleArgs),
    /// Check SoD for an agent-tool combination
    Check(SodCheckArgs),
}

#[derive(Args, Debug)]
pub struct SodCreateRuleArgs {
    /// First tool ID
    #[arg(long)]
    pub tool_a: String,
    /// Second tool ID
    #[arg(long)]
    pub tool_b: String,
    /// Enforcement: prevent or warn
    #[arg(long)]
    pub enforcement: String,
    /// Rule description
    #[arg(long, short = 'd')]
    pub description: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SodDeleteRuleArgs {
    /// SoD rule ID (UUID)
    pub id: String,
    /// Skip confirmation prompt
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct SodCheckArgs {
    /// Agent NHI identity ID
    #[arg(long)]
    pub agent: String,
    /// Tool NHI identity ID
    #[arg(long)]
    pub tool: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// --- Inactivity ---

#[derive(Subcommand, Debug)]
pub enum InactivityCommands {
    /// Detect inactive NHI identities
    Detect(JsonOnlyArgs),
    /// Auto-suspend inactive NHI identities
    AutoSuspend(JsonOnlyArgs),
    /// Set a grace period before auto-suspend
    GracePeriod(GracePeriodArgs),
}

#[derive(Args, Debug)]
pub struct GracePeriodArgs {
    /// NHI identity ID (UUID)
    pub id: String,
    /// Grace period in days
    #[arg(long)]
    pub days: i32,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// --- Orphans ---

#[derive(Subcommand, Debug)]
pub enum OrphansCommands {
    /// Detect orphaned NHI identities
    Detect(JsonOnlyArgs),
}

// =============================================================================
// Execution
// =============================================================================

pub async fn execute(args: NhiArgs) -> CliResult<()> {
    match args.command {
        NhiCommands::List(a) => execute_list(a).await,
        NhiCommands::Get(a) => execute_get(a).await,
        NhiCommands::Suspend(a) => execute_suspend(a).await,
        NhiCommands::Reactivate(a) => execute_lifecycle(a, "reactivate").await,
        NhiCommands::Deprecate(a) => execute_lifecycle(a, "deprecate").await,
        NhiCommands::Archive(a) => execute_lifecycle(a, "archive").await,
        NhiCommands::Deactivate(a) => execute_lifecycle(a, "deactivate").await,
        NhiCommands::Activate(a) => execute_lifecycle(a, "activate").await,
        NhiCommands::Credentials(c) => execute_credentials(c).await,
        NhiCommands::Permissions(p) => execute_permissions(p).await,
        NhiCommands::Risk(a) => execute_risk(a).await,
        NhiCommands::RiskSummary(a) => execute_risk_summary(a).await,
        NhiCommands::Certifications(c) => execute_certifications(c).await,
        NhiCommands::Sod(s) => execute_sod(s).await,
        NhiCommands::Inactivity(i) => execute_inactivity(i).await,
        NhiCommands::Orphans(o) => execute_orphans(o).await,
    }
}

// --- List / Get ---

async fn execute_list(args: ListArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;
    let owner = args.owner.as_deref().map(parse_uuid).transpose()?;

    let response = client
        .list_nhi(
            args.limit,
            args.offset,
            args.r#type.as_deref(),
            args.state.as_deref(),
            owner,
        )
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No NHI identities found.");
    } else {
        print_nhi_table(&response.data);
        println!();
        println!(
            "Showing {} of {} identities",
            response.data.len(),
            response.total
        );
    }

    Ok(())
}

async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let identity = client.get_nhi(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&identity)?);
    } else {
        print_nhi_details(&identity);
    }

    Ok(())
}

// --- Lifecycle ---

async fn execute_suspend(args: SuspendArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let request = SuspendRequest {
        reason: args.reason,
    };
    let result = client.nhi_suspend(id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Suspended: {} (state: {})",
            result.name, result.lifecycle_state
        );
    }

    Ok(())
}

async fn execute_lifecycle(args: IdJsonArgs, action: &str) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let result = match action {
        "reactivate" => client.nhi_reactivate(id).await?,
        "deprecate" => client.nhi_deprecate(id).await?,
        "archive" => client.nhi_archive(id).await?,
        "deactivate" => client.nhi_deactivate(id).await?,
        "activate" => client.nhi_activate(id).await?,
        _ => unreachable!(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let action_past = match action {
            "reactivate" => "Reactivated",
            "deprecate" => "Deprecated",
            "archive" => "Archived",
            "deactivate" => "Deactivated",
            "activate" => "Activated",
            _ => action,
        };
        println!(
            "{}: {} (state: {})",
            action_past, result.name, result.lifecycle_state
        );
    }

    Ok(())
}

// --- Credentials ---

async fn execute_credentials(cmd: CredentialsCommands) -> CliResult<()> {
    match cmd {
        CredentialsCommands::Issue(a) => execute_cred_issue(a).await,
        CredentialsCommands::List(a) => execute_cred_list(a).await,
        CredentialsCommands::Rotate(a) => execute_cred_rotate(a).await,
        CredentialsCommands::Revoke(a) => execute_cred_revoke(a).await,
    }
}

async fn execute_cred_issue(args: CredIssueArgs) -> CliResult<()> {
    let nhi_id = parse_uuid(&args.nhi_id)?;
    let client = ApiClient::from_defaults()?;

    let request = IssueCredentialRequest {
        credential_type: args.r#type,
        valid_days: args.valid_days,
    };
    let result = client.nhi_issue_credential(nhi_id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Credential issued successfully!");
        println!();
        print_credential_details(&result.credential);
        if let Some(ref secret) = result.secret {
            println!();
            println!("Secret (save this now, it will not be shown again):");
            println!("  {secret}");
        }
        if let Some(ref api_key) = result.api_key {
            println!();
            println!("API Key (save this now, it will not be shown again):");
            println!("  {api_key}");
        }
    }

    Ok(())
}

async fn execute_cred_list(args: CredListArgs) -> CliResult<()> {
    let nhi_id = parse_uuid(&args.nhi_id)?;
    let client = ApiClient::from_defaults()?;

    let response = client.nhi_list_credentials(nhi_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No credentials found for this identity.");
    } else {
        print_credential_table(&response.data);
        println!();
        println!("Total: {} credentials", response.total);
    }

    Ok(())
}

async fn execute_cred_rotate(args: CredRotateArgs) -> CliResult<()> {
    let nhi_id = parse_uuid(&args.nhi_id)?;
    let credential_id = parse_uuid(&args.credential_id)?;
    let client = ApiClient::from_defaults()?;

    let request = RotateCredentialRequest {
        grace_period_hours: args.grace_period_hours,
    };
    let result = client
        .nhi_rotate_credential(nhi_id, credential_id, request)
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Credential rotated successfully!");
        println!();
        print_credential_details(&result.credential);
        if let Some(ref secret) = result.secret {
            println!();
            println!("New secret (save this now):");
            println!("  {secret}");
        }
        if let Some(ref api_key) = result.api_key {
            println!();
            println!("New API key (save this now):");
            println!("  {api_key}");
        }
    }

    Ok(())
}

async fn execute_cred_revoke(args: CredRevokeArgs) -> CliResult<()> {
    let nhi_id = parse_uuid(&args.nhi_id)?;
    let credential_id = parse_uuid(&args.credential_id)?;
    let client = ApiClient::from_defaults()?;

    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Use --force in non-interactive mode.".to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt("Revoke this credential? This action cannot be undone.")
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    client.nhi_revoke_credential(nhi_id, credential_id).await?;
    println!("Credential revoked: {credential_id}");

    Ok(())
}

// --- Permissions ---

async fn execute_permissions(cmd: PermissionsCommands) -> CliResult<()> {
    match cmd {
        PermissionsCommands::Grant(a) => execute_perm_grant(a).await,
        PermissionsCommands::Revoke(a) => execute_perm_revoke(a).await,
        PermissionsCommands::ListTools(a) => execute_perm_list_tools(a).await,
        PermissionsCommands::ListAgents(a) => execute_perm_list_agents(a).await,
    }
}

async fn execute_perm_grant(args: PermGrantArgs) -> CliResult<()> {
    let agent_id = parse_uuid(&args.agent)?;
    let tool_id = parse_uuid(&args.tool)?;
    let client = ApiClient::from_defaults()?;

    let request = GrantPermissionRequest {
        expires_at: args.expires_at,
    };
    let result = client
        .nhi_grant_permission(agent_id, tool_id, request)
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Permission granted!");
        print_permission_details(&result);
    }

    Ok(())
}

async fn execute_perm_revoke(args: PermRevokeArgs) -> CliResult<()> {
    let agent_id = parse_uuid(&args.agent)?;
    let tool_id = parse_uuid(&args.tool)?;
    let client = ApiClient::from_defaults()?;

    let result = client.nhi_revoke_permission(agent_id, tool_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.revoked {
        println!("Permission revoked.");
    } else {
        println!(
            "{}",
            result
                .message
                .unwrap_or_else(|| "Permission not found or already revoked.".to_string())
        );
    }

    Ok(())
}

async fn execute_perm_list_tools(args: PermListToolsArgs) -> CliResult<()> {
    let agent_id = parse_uuid(&args.agent)?;
    let client = ApiClient::from_defaults()?;

    let response = client.nhi_list_agent_tools(agent_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No tool permissions found for this agent.");
    } else {
        print_permission_table(&response.data);
        println!();
        println!("Total: {} permissions", response.total);
    }

    Ok(())
}

async fn execute_perm_list_agents(args: PermListAgentsArgs) -> CliResult<()> {
    let tool_id = parse_uuid(&args.tool)?;
    let client = ApiClient::from_defaults()?;

    let response = client.nhi_list_tool_agents(tool_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No agents have permission to this tool.");
    } else {
        print_permission_table(&response.data);
        println!();
        println!("Total: {} permissions", response.total);
    }

    Ok(())
}

// --- Risk ---

async fn execute_risk(args: RiskArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let result = client.nhi_risk(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Risk Assessment: {}", result.nhi_identity_id);
        println!("{}", "\u{2501}".repeat(50));
        if let Some(ref risk) = result.overall_risk {
            println!("Overall Risk:  {risk}");
        }
        if let Some(score) = result.risk_score {
            println!("Risk Score:    {score:.1}");
        }
        if !result.factors.is_empty() {
            println!();
            print_risk_factors(&result.factors);
        }
    }

    Ok(())
}

async fn execute_risk_summary(args: JsonOnlyArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let result = client.nhi_risk_summary().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("NHI Risk Summary");
        println!("{}", "\u{2501}".repeat(40));
        println!("Total Identities: {}", result.total_identities);
        println!("Critical Risk:    {}", result.critical_risk_count);
        println!("High Risk:        {}", result.high_risk_count);
        println!("Medium Risk:      {}", result.medium_risk_count);
        println!("Low Risk:         {}", result.low_risk_count);
    }

    Ok(())
}

// --- Certifications ---

async fn execute_certifications(cmd: CertificationsCommands) -> CliResult<()> {
    match cmd {
        CertificationsCommands::Create(a) => execute_cert_create(a).await,
        CertificationsCommands::List(a) => execute_cert_list(a).await,
        CertificationsCommands::Certify(a) => execute_cert_certify(a).await,
        CertificationsCommands::Revoke(a) => execute_cert_revoke(a).await,
    }
}

async fn execute_cert_create(args: CertCreateArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let request = CreateCampaignRequest {
        name: args.name,
        description: args.description,
        scope: args.scope,
        due_date: args.due_date,
        scope_filter: None,
    };
    let result = client.nhi_create_campaign(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Certification campaign created!");
        println!();
        print_campaign_details(&result);
    }

    Ok(())
}

async fn execute_cert_list(args: CertListArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let response = client.nhi_list_campaigns(args.status.as_deref()).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No certification campaigns found.");
    } else {
        print_campaign_table(&response.data);
        println!();
        println!("Total: {} campaigns", response.total);
    }

    Ok(())
}

async fn execute_cert_certify(args: CertActionArgs) -> CliResult<()> {
    let campaign_id = parse_uuid(&args.campaign_id)?;
    let nhi_id = parse_uuid(&args.nhi_id)?;
    let client = ApiClient::from_defaults()?;

    let result = client.nhi_certify(campaign_id, nhi_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("NHI identity {} certified.", result.nhi_id);
        if let Some(ref next) = result.next_certification_at {
            println!("Next certification due: {next}");
        }
    }

    Ok(())
}

async fn execute_cert_revoke(args: CertActionArgs) -> CliResult<()> {
    let campaign_id = parse_uuid(&args.campaign_id)?;
    let nhi_id = parse_uuid(&args.nhi_id)?;
    let client = ApiClient::from_defaults()?;

    let result = client.nhi_revoke_cert(campaign_id, nhi_id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.revoked {
        println!("Certification revoked for {}.", result.nhi_id);
        if let Some(ref state) = result.new_state {
            println!("New state: {state}");
        }
    } else {
        println!(
            "{}",
            result
                .message
                .unwrap_or_else(|| "Certification not found or already revoked.".to_string())
        );
    }

    Ok(())
}

// --- SoD ---

async fn execute_sod(cmd: SodCommands) -> CliResult<()> {
    match cmd {
        SodCommands::CreateRule(a) => execute_sod_create_rule(a).await,
        SodCommands::ListRules(a) => execute_sod_list_rules(a).await,
        SodCommands::DeleteRule(a) => execute_sod_delete_rule(a).await,
        SodCommands::Check(a) => execute_sod_check(a).await,
    }
}

async fn execute_sod_create_rule(args: SodCreateRuleArgs) -> CliResult<()> {
    let tool_a = parse_uuid(&args.tool_a)?;
    let tool_b = parse_uuid(&args.tool_b)?;
    let client = ApiClient::from_defaults()?;

    validate_enforcement(&args.enforcement)?;

    let request = CreateSodRuleRequest {
        tool_id_a: tool_a,
        tool_id_b: tool_b,
        enforcement: args.enforcement,
        description: args.description,
    };
    let result = client.nhi_create_sod_rule(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("SoD rule created!");
        println!();
        print_sod_rule_details(&result);
    }

    Ok(())
}

async fn execute_sod_list_rules(args: JsonOnlyArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let response = client.nhi_list_sod_rules().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No SoD rules found.");
    } else {
        print_sod_rule_table(&response.data);
        println!();
        println!("Total: {} rules", response.total);
    }

    Ok(())
}

async fn execute_sod_delete_rule(args: SodDeleteRuleArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Use --force in non-interactive mode.".to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt("Delete this SoD rule?")
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    client.nhi_delete_sod_rule(id).await?;
    println!("SoD rule deleted: {id}");

    Ok(())
}

async fn execute_sod_check(args: SodCheckArgs) -> CliResult<()> {
    let agent_id = parse_uuid(&args.agent)?;
    let tool_id = parse_uuid(&args.tool)?;
    let client = ApiClient::from_defaults()?;

    let request = SodCheckRequest { agent_id, tool_id };
    let result = client.nhi_sod_check(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.is_allowed {
        println!("ALLOWED: No SoD violations detected.");
    } else {
        println!("BLOCKED: SoD violations detected!");
        println!();
        for v in &result.violations {
            println!("  Rule:        {}", v.rule_id);
            println!("  Enforcement: {}", v.enforcement);
            if let Some(ref conflict) = v.conflicting_tool_id {
                println!("  Conflict:    {conflict}");
            }
            if let Some(ref desc) = v.description {
                println!("  Reason:      {desc}");
            }
            println!();
        }
    }

    Ok(())
}

// --- Inactivity ---

async fn execute_inactivity(cmd: InactivityCommands) -> CliResult<()> {
    match cmd {
        InactivityCommands::Detect(a) => execute_inactivity_detect(a).await,
        InactivityCommands::AutoSuspend(a) => execute_inactivity_auto_suspend(a).await,
        InactivityCommands::GracePeriod(a) => execute_inactivity_grace_period(a).await,
    }
}

async fn execute_inactivity_detect(args: JsonOnlyArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let response = client.nhi_detect_inactive().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No inactive NHI identities detected.");
    } else {
        print_inactive_table(&response.data);
        println!();
        println!("Total: {} inactive identities", response.total);
    }

    Ok(())
}

async fn execute_inactivity_auto_suspend(args: JsonOnlyArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let result = client.nhi_auto_suspend().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_auto_suspend_result(&result);
    }

    Ok(())
}

async fn execute_inactivity_grace_period(args: GracePeriodArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let request = GracePeriodRequest {
        grace_days: args.days,
    };
    let result = client.nhi_grace_period(id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Grace period set for {}", result.id);
        if let Some(ref until) = result.grace_until {
            println!("Grace until: {until}");
        }
        if let Some(ref msg) = result.message {
            println!("{msg}");
        }
    }

    Ok(())
}

// --- Orphans ---

async fn execute_orphans(cmd: OrphansCommands) -> CliResult<()> {
    match cmd {
        OrphansCommands::Detect(a) => execute_orphans_detect(a).await,
    }
}

async fn execute_orphans_detect(args: JsonOnlyArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let response = client.nhi_detect_orphans().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.data.is_empty() {
        println!("No orphaned NHI identities detected.");
    } else {
        print_orphan_table(&response.data);
        println!();
        println!("Total: {} orphaned identities", response.total);
    }

    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

fn parse_uuid(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str)
        .map_err(|_| CliError::Validation(format!("Invalid ID '{id_str}'. Must be a valid UUID.")))
}

fn validate_enforcement(enforcement: &str) -> CliResult<()> {
    match enforcement {
        "prevent" | "warn" => Ok(()),
        _ => Err(CliError::Validation(format!(
            "Invalid enforcement '{enforcement}'. Must be 'prevent' or 'warn'."
        ))),
    }
}

// --- Display helpers ---

fn print_nhi_table(identities: &[NhiIdentityResponse]) {
    println!(
        "{:<38} {:<22} {:<17} {:<12} {:<10}",
        "ID", "NAME", "TYPE", "STATE", "RISK"
    );
    println!("{}", "-".repeat(101));

    for nhi in identities {
        let name = truncate(&nhi.name, 20);
        let risk = nhi.risk_level.as_deref().unwrap_or("-");
        println!(
            "{:<38} {:<22} {:<17} {:<12} {:<10}",
            nhi.id, name, nhi.nhi_type, nhi.lifecycle_state, risk
        );
    }
}

fn print_nhi_details(nhi: &NhiIdentityResponse) {
    println!("NHI Identity: {}", nhi.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:              {}", nhi.id);
    println!("Type:            {}", nhi.nhi_type);
    println!("State:           {}", nhi.lifecycle_state);

    if let Some(ref desc) = nhi.description {
        println!("Description:     {desc}");
    }
    if let Some(ref risk) = nhi.risk_level {
        println!("Risk Level:      {risk}");
    }
    if let Some(ref owner) = nhi.owner_id {
        println!("Owner:           {owner}");
    }
    if let Some(ref backup) = nhi.backup_owner_id {
        println!("Backup Owner:    {backup}");
    }

    println!(
        "Created:         {}",
        nhi.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Updated:         {}",
        nhi.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_credential_table(creds: &[NhiCredentialResponse]) {
    println!(
        "{:<38} {:<15} {:<8} {:<25} {:<25}",
        "ID", "TYPE", "ACTIVE", "EXPIRES", "CREATED"
    );
    println!("{}", "-".repeat(113));

    for c in creds {
        let expires = c
            .expires_at
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "-".to_string());
        let created = c.created_at.format("%Y-%m-%d %H:%M UTC").to_string();
        println!(
            "{:<38} {:<15} {:<8} {:<25} {:<25}",
            c.id,
            c.credential_type,
            if c.is_active { "Yes" } else { "No" },
            expires,
            created
        );
    }
}

fn print_credential_details(cred: &NhiCredentialResponse) {
    println!("Credential: {}", cred.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("Identity:    {}", cred.nhi_identity_id);
    println!("Type:        {}", cred.credential_type);
    println!("Active:      {}", if cred.is_active { "Yes" } else { "No" });
    if let Some(ref exp) = cred.expires_at {
        println!("Expires:     {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    println!(
        "Created:     {}",
        cred.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(ref rot) = cred.rotated_at {
        println!("Rotated:     {}", rot.format("%Y-%m-%d %H:%M:%S UTC"));
    }
}

fn print_permission_table(perms: &[PermissionResponse]) {
    println!(
        "{:<38} {:<38} {:<38} {:<25}",
        "ID", "AGENT", "TOOL", "EXPIRES"
    );
    println!("{}", "-".repeat(141));

    for p in perms {
        let expires = p
            .expires_at
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<38} {:<38} {:<38} {:<25}",
            p.id, p.agent_identity_id, p.tool_identity_id, expires
        );
    }
}

fn print_permission_details(perm: &PermissionResponse) {
    println!("Permission: {}", perm.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("Agent:      {}", perm.agent_identity_id);
    println!("Tool:       {}", perm.tool_identity_id);
    if let Some(ref by) = perm.granted_by {
        println!("Granted By: {by}");
    }
    if let Some(ref exp) = perm.expires_at {
        println!("Expires:    {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    println!(
        "Created:    {}",
        perm.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_risk_factors(factors: &[RiskFactor]) {
    println!("Risk Factors:");
    println!("{:<25} {:<12} {:<30}", "FACTOR", "SEVERITY", "DESCRIPTION");
    println!("{}", "-".repeat(70));

    for f in factors {
        let severity = f.severity.as_deref().unwrap_or("-");
        let desc = f.description.as_deref().unwrap_or("-");
        println!(
            "{:<25} {:<12} {:<30}",
            truncate(&f.name, 23),
            severity,
            desc
        );
    }
}

fn print_campaign_table(campaigns: &[CampaignResponse]) {
    println!(
        "{:<38} {:<25} {:<12} {:<12} {:<15}",
        "ID", "NAME", "SCOPE", "STATUS", "DUE DATE"
    );
    println!("{}", "-".repeat(104));

    for c in campaigns {
        let name = truncate(&c.name, 23);
        let scope = c.scope.as_deref().unwrap_or("-");
        let status = c.status.as_deref().unwrap_or("-");
        let due = c.due_date.as_deref().unwrap_or("-");
        println!(
            "{:<38} {:<25} {:<12} {:<12} {:<15}",
            c.id, name, scope, status, due
        );
    }
}

fn print_campaign_details(c: &CampaignResponse) {
    println!("Campaign: {}", c.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", c.id);
    if let Some(ref desc) = c.description {
        println!("Description: {desc}");
    }
    if let Some(ref scope) = c.scope {
        println!("Scope:       {scope}");
    }
    if let Some(ref status) = c.status {
        println!("Status:      {status}");
    }
    if let Some(ref due) = c.due_date {
        println!("Due Date:    {due}");
    }
    println!(
        "Created:     {}",
        c.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_sod_rule_table(rules: &[SodRuleResponse]) {
    println!(
        "{:<38} {:<38} {:<38} {:<10}",
        "ID", "TOOL A", "TOOL B", "ENFORCE"
    );
    println!("{}", "-".repeat(126));

    for r in rules {
        println!(
            "{:<38} {:<38} {:<38} {:<10}",
            r.id, r.tool_id_a, r.tool_id_b, r.enforcement
        );
    }
}

fn print_sod_rule_details(r: &SodRuleResponse) {
    println!("SoD Rule: {}", r.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("Tool A:      {}", r.tool_id_a);
    println!("Tool B:      {}", r.tool_id_b);
    println!("Enforcement: {}", r.enforcement);
    if let Some(ref desc) = r.description {
        println!("Description: {desc}");
    }
    println!(
        "Created:     {}",
        r.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_inactive_table(entities: &[InactiveEntity]) {
    println!(
        "{:<38} {:<22} {:<17} {:<12} {:<10}",
        "ID", "NAME", "TYPE", "STATE", "DAYS"
    );
    println!("{}", "-".repeat(101));

    for e in entities {
        let name = truncate(&e.name, 20);
        let days = e
            .inactive_days
            .map(|d| d.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<38} {:<22} {:<17} {:<12} {:<10}",
            e.id, name, e.nhi_type, e.lifecycle_state, days
        );
    }
}

fn print_auto_suspend_result(result: &AutoSuspendResponse) {
    println!("Auto-suspend complete.");
    println!("Suspended: {} identities", result.suspended_count);
    if !result.suspended_ids.is_empty() {
        println!();
        for id in &result.suspended_ids {
            println!("  {id}");
        }
    }
    if let Some(ref msg) = result.message {
        println!();
        println!("{msg}");
    }
}

fn print_orphan_table(entities: &[OrphanEntity]) {
    println!(
        "{:<38} {:<22} {:<17} {:<12} {:<38}",
        "ID", "NAME", "TYPE", "STATE", "OWNER"
    );
    println!("{}", "-".repeat(129));

    for e in entities {
        let name = truncate(&e.name, 20);
        let owner = e
            .owner_id
            .map(|o| o.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<38} {:<22} {:<17} {:<12} {:<38}",
            e.id, name, e.nhi_type, e.lifecycle_state, owner
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid_valid() {
        let valid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_uuid(valid).is_ok());
    }

    #[test]
    fn test_parse_uuid_invalid() {
        let result = parse_uuid("not-a-uuid");
        assert!(result.is_err());
        if let Err(CliError::Validation(msg)) = result {
            assert!(msg.contains("UUID"));
        }
    }

    #[test]
    fn test_validate_enforcement_valid() {
        assert!(validate_enforcement("prevent").is_ok());
        assert!(validate_enforcement("warn").is_ok());
    }

    #[test]
    fn test_validate_enforcement_invalid() {
        assert!(validate_enforcement("block").is_err());
        assert!(validate_enforcement("PREVENT").is_err());
    }
}
