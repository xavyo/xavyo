//! Governance CLI commands (roles, entitlements, access requests, archetypes, lifecycle, SoD, etc.)

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::governance::{
    AccessRequestResponse, ArchetypeResponse, BulkActionResponse, CampaignResponse,
    CatalogItemResponse, CreateAccessRequest, DelegationResponse, EntitlementResponse,
    LifecycleConfigResponse, ObjectTemplateResponse, ReportResponse, RiskAlertResponse,
    RoleResponse, SodRuleResponse, SodViolationResponse,
};
use crate::output::{truncate, validate_pagination};
use clap::{Args, Subcommand};
use uuid::Uuid;

/// Governance commands
#[derive(Args, Debug)]
pub struct GovernanceArgs {
    #[command(subcommand)]
    pub command: GovernanceCommands,
}

#[derive(Subcommand, Debug)]
pub enum GovernanceCommands {
    /// Manage governance roles
    #[command(subcommand)]
    Roles(RolesCommands),
    /// Manage entitlements
    #[command(subcommand)]
    Entitlements(EntitlementsCommands),
    /// Manage access requests
    #[command(subcommand)]
    AccessRequests(AccessRequestsCommands),
    /// Manage identity archetypes
    #[command(subcommand)]
    Archetypes(ArchetypesCommands),
    /// Manage lifecycle configurations
    #[command(subcommand)]
    Lifecycle(LifecycleCommands),
    /// Separation of Duties (SoD) rules and violations
    #[command(subcommand)]
    Sod(SodCommands),
    /// Certification campaigns
    #[command(subcommand)]
    Campaigns(CampaignsCommands),
    /// Object templates
    #[command(subcommand)]
    Templates(TemplatesCommands),
    /// Self-service request catalog
    #[command(subcommand)]
    Catalog(CatalogCommands),
    /// Bulk action engine
    #[command(subcommand)]
    BulkActions(BulkActionsCommands),
    /// Delegations
    #[command(subcommand)]
    Delegations(DelegationsCommands),
    /// GDPR data protection
    #[command(subcommand)]
    Gdpr(GdprCommands),
    /// Risk scoring and alerts
    #[command(subcommand)]
    Risk(RiskCommands),
    /// Compliance reports
    #[command(subcommand)]
    Reports(ReportsCommands),
    /// Approval workflows
    #[command(subcommand)]
    Workflows(WorkflowsCommands),
}

// --- Roles ---

#[derive(Subcommand, Debug)]
pub enum RolesCommands {
    /// List governance roles
    List(PaginationArgs),
    /// Get a specific role
    Get(IdJsonArgs),
}

// --- Entitlements ---

#[derive(Subcommand, Debug)]
pub enum EntitlementsCommands {
    /// List entitlements
    List(PaginationArgs),
    /// Get a specific entitlement
    Get(IdJsonArgs),
}

// --- Access Requests ---

#[derive(Subcommand, Debug)]
pub enum AccessRequestsCommands {
    /// List access requests
    List(PaginationArgs),
    /// Get a specific access request
    Get(IdJsonArgs),
    /// Create a new access request
    Create(CreateAccessRequestArgs),
    /// Cancel an access request
    Cancel(IdOnlyArgs),
}

// --- Archetypes ---

#[derive(Subcommand, Debug)]
pub enum ArchetypesCommands {
    /// List identity archetypes
    List(PaginationArgs),
    /// Get a specific archetype
    Get(IdJsonArgs),
}

// --- Lifecycle ---

#[derive(Subcommand, Debug)]
pub enum LifecycleCommands {
    /// List lifecycle configurations
    List(PaginationArgs),
    /// Get a specific lifecycle config
    Get(IdJsonArgs),
}

// --- SoD ---

#[derive(Subcommand, Debug)]
pub enum SodCommands {
    /// List SoD rules
    Rules(PaginationArgs),
    /// Get a specific SoD rule
    GetRule(IdJsonArgs),
    /// Enable a SoD rule
    Enable(IdOnlyArgs),
    /// Disable a SoD rule
    Disable(IdOnlyArgs),
    /// List SoD violations
    Violations(PaginationArgs),
}

// --- Campaigns ---

#[derive(Subcommand, Debug)]
pub enum CampaignsCommands {
    /// List certification campaigns
    List(PaginationArgs),
    /// Get a specific campaign
    Get(IdJsonArgs),
    /// Launch a campaign
    Launch(IdOnlyArgs),
    /// Cancel a campaign
    Cancel(IdOnlyArgs),
}

// --- Templates ---

#[derive(Subcommand, Debug)]
pub enum TemplatesCommands {
    /// List object templates
    List(PaginationArgs),
    /// Get a specific template
    Get(IdJsonArgs),
}

// --- Catalog ---

#[derive(Subcommand, Debug)]
pub enum CatalogCommands {
    /// List catalog categories
    Categories(PaginationArgs),
    /// List catalog items
    Items(PaginationArgs),
    /// Get a specific catalog item
    GetItem(IdJsonArgs),
}

// --- Bulk Actions ---

#[derive(Subcommand, Debug)]
pub enum BulkActionsCommands {
    /// List bulk actions
    List(PaginationArgs),
    /// Get a specific bulk action
    Get(IdJsonArgs),
}

// --- Delegations ---

#[derive(Subcommand, Debug)]
pub enum DelegationsCommands {
    /// List my delegations
    List(PaginationArgs),
    /// Get a specific delegation
    Get(IdJsonArgs),
    /// Revoke a delegation
    Revoke(IdOnlyArgs),
}

// --- GDPR ---

#[derive(Subcommand, Debug)]
pub enum GdprCommands {
    /// Get GDPR data protection report
    Report,
}

// --- Risk ---

#[derive(Subcommand, Debug)]
pub enum RiskCommands {
    /// Get risk score for a user
    Score(IdJsonArgs),
    /// List risk alerts
    Alerts(PaginationArgs),
    /// Acknowledge a risk alert
    Acknowledge(IdOnlyArgs),
}

// --- Reports ---

#[derive(Subcommand, Debug)]
pub enum ReportsCommands {
    /// List compliance reports
    List(PaginationArgs),
    /// Get a specific report
    Get(IdJsonArgs),
}

// --- Workflows ---

#[derive(Subcommand, Debug)]
pub enum WorkflowsCommands {
    /// List approval workflows
    List(PaginationArgs),
    /// Get a specific workflow
    Get(IdJsonArgs),
}

// --- Shared argument structs ---

#[derive(Args, Debug)]
pub struct PaginationArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value = "50")]
    pub limit: i32,
    #[arg(long, default_value = "0")]
    pub offset: i32,
}

#[derive(Args, Debug)]
pub struct IdJsonArgs {
    pub id: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct IdOnlyArgs {
    pub id: String,
}

#[derive(Args, Debug)]
pub struct CreateAccessRequestArgs {
    /// Target resource ID (role or entitlement UUID)
    #[arg(long)]
    pub target_id: String,

    /// Request type (e.g., role_assignment, entitlement_grant)
    #[arg(long)]
    pub request_type: String,

    /// Justification for the request
    #[arg(long, short = 'j')]
    pub justification: Option<String>,

    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: GovernanceArgs) -> CliResult<()> {
    match args.command {
        GovernanceCommands::Roles(cmd) => execute_roles(cmd).await,
        GovernanceCommands::Entitlements(cmd) => execute_entitlements(cmd).await,
        GovernanceCommands::AccessRequests(cmd) => execute_access_requests(cmd).await,
        GovernanceCommands::Archetypes(cmd) => execute_archetypes(cmd).await,
        GovernanceCommands::Lifecycle(cmd) => execute_lifecycle(cmd).await,
        GovernanceCommands::Sod(cmd) => execute_sod(cmd).await,
        GovernanceCommands::Campaigns(cmd) => execute_campaigns(cmd).await,
        GovernanceCommands::Templates(cmd) => execute_templates(cmd).await,
        GovernanceCommands::Catalog(cmd) => execute_catalog(cmd).await,
        GovernanceCommands::BulkActions(cmd) => execute_bulk_actions(cmd).await,
        GovernanceCommands::Delegations(cmd) => execute_delegations(cmd).await,
        GovernanceCommands::Gdpr(cmd) => execute_gdpr(cmd).await,
        GovernanceCommands::Risk(cmd) => execute_risk(cmd).await,
        GovernanceCommands::Reports(cmd) => execute_reports(cmd).await,
        GovernanceCommands::Workflows(cmd) => execute_workflows(cmd).await,
    }
}

// --- Roles execution ---

async fn execute_roles(cmd: RolesCommands) -> CliResult<()> {
    match cmd {
        RolesCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_roles(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.roles.is_empty() {
                println!("No roles found.");
            } else {
                print_role_table(&response.roles);
                println!(
                    "\nShowing {} of {} roles",
                    response.roles.len(),
                    response.total
                );
            }
            Ok(())
        }
        RolesCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let role = client.get_role(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&role)?);
            } else {
                print_role_details(&role);
            }
            Ok(())
        }
    }
}

// --- Entitlements execution ---

async fn execute_entitlements(cmd: EntitlementsCommands) -> CliResult<()> {
    match cmd {
        EntitlementsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_entitlements(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.entitlements.is_empty() {
                println!("No entitlements found.");
            } else {
                print_entitlement_table(&response.entitlements);
                println!(
                    "\nShowing {} of {} entitlements",
                    response.entitlements.len(),
                    response.total
                );
            }
            Ok(())
        }
        EntitlementsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let ent = client.get_entitlement(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&ent)?);
            } else {
                print_entitlement_details(&ent);
            }
            Ok(())
        }
    }
}

// --- Access Requests execution ---

async fn execute_access_requests(cmd: AccessRequestsCommands) -> CliResult<()> {
    match cmd {
        AccessRequestsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_access_requests(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.access_requests.is_empty() {
                println!("No access requests found.");
            } else {
                print_ar_table(&response.access_requests);
                println!(
                    "\nShowing {} of {} access requests",
                    response.access_requests.len(),
                    response.total
                );
            }
            Ok(())
        }
        AccessRequestsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let ar = client.get_access_request(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&ar)?);
            } else {
                print_ar_details(&ar);
            }
            Ok(())
        }
        AccessRequestsCommands::Create(a) => {
            let target_id = parse_uuid(&a.target_id)?;
            let client = ApiClient::from_defaults()?;
            let request = CreateAccessRequest {
                target_id,
                request_type: a.request_type,
                justification: a.justification,
            };
            let ar = client.create_access_request(request).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&ar)?);
            } else {
                println!("Access request created successfully!");
                println!();
                print_ar_details(&ar);
            }
            Ok(())
        }
        AccessRequestsCommands::Cancel(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.cancel_access_request(id).await?;
            println!("Access request cancelled.");
            Ok(())
        }
    }
}

// --- Archetypes execution ---

async fn execute_archetypes(cmd: ArchetypesCommands) -> CliResult<()> {
    match cmd {
        ArchetypesCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_archetypes(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.archetypes.is_empty() {
                println!("No archetypes found.");
            } else {
                print_archetype_table(&response.archetypes);
                println!(
                    "\nShowing {} of {} archetypes",
                    response.archetypes.len(),
                    response.total
                );
            }
            Ok(())
        }
        ArchetypesCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let archetype = client.get_archetype(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&archetype)?);
            } else {
                print_archetype_details(&archetype);
            }
            Ok(())
        }
    }
}

// --- Lifecycle execution ---

async fn execute_lifecycle(cmd: LifecycleCommands) -> CliResult<()> {
    match cmd {
        LifecycleCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_lifecycle_configs(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.configs.is_empty() {
                println!("No lifecycle configurations found.");
            } else {
                print_lifecycle_table(&response.configs);
                println!(
                    "\nShowing {} of {} configs",
                    response.configs.len(),
                    response.total
                );
            }
            Ok(())
        }
        LifecycleCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let config = client.get_lifecycle_config(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&config)?);
            } else {
                print_lifecycle_details(&config);
            }
            Ok(())
        }
    }
}

// --- SoD execution ---

async fn execute_sod(cmd: SodCommands) -> CliResult<()> {
    match cmd {
        SodCommands::Rules(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_sod_rules(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.rules.is_empty() {
                println!("No SoD rules found.");
            } else {
                print_sod_rule_table(&response.rules);
                println!(
                    "\nShowing {} of {} rules",
                    response.rules.len(),
                    response.total
                );
            }
            Ok(())
        }
        SodCommands::GetRule(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let rule = client.get_sod_rule(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&rule)?);
            } else {
                print_sod_rule_details(&rule);
            }
            Ok(())
        }
        SodCommands::Enable(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.enable_sod_rule(id).await?;
            println!("SoD rule enabled.");
            Ok(())
        }
        SodCommands::Disable(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.disable_sod_rule(id).await?;
            println!("SoD rule disabled.");
            Ok(())
        }
        SodCommands::Violations(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_sod_violations(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.violations.is_empty() {
                println!("No SoD violations found.");
            } else {
                print_violation_table(&response.violations);
                println!(
                    "\nShowing {} of {} violations",
                    response.violations.len(),
                    response.total
                );
            }
            Ok(())
        }
    }
}

// --- Campaigns execution ---

async fn execute_campaigns(cmd: CampaignsCommands) -> CliResult<()> {
    match cmd {
        CampaignsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_campaigns(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.campaigns.is_empty() {
                println!("No campaigns found.");
            } else {
                print_campaign_table(&response.campaigns);
                println!(
                    "\nShowing {} of {} campaigns",
                    response.campaigns.len(),
                    response.total
                );
            }
            Ok(())
        }
        CampaignsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let campaign = client.get_campaign(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&campaign)?);
            } else {
                print_campaign_details(&campaign);
            }
            Ok(())
        }
        CampaignsCommands::Launch(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.launch_campaign(id).await?;
            println!("Campaign launched.");
            Ok(())
        }
        CampaignsCommands::Cancel(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.cancel_campaign(id).await?;
            println!("Campaign cancelled.");
            Ok(())
        }
    }
}

// --- Templates execution ---

async fn execute_templates(cmd: TemplatesCommands) -> CliResult<()> {
    match cmd {
        TemplatesCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_object_templates(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.templates.is_empty() {
                println!("No object templates found.");
            } else {
                print_template_table(&response.templates);
                println!(
                    "\nShowing {} of {} templates",
                    response.templates.len(),
                    response.total
                );
            }
            Ok(())
        }
        TemplatesCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let template = client.get_object_template(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&template)?);
            } else {
                print_template_details(&template);
            }
            Ok(())
        }
    }
}

// --- Catalog execution ---

async fn execute_catalog(cmd: CatalogCommands) -> CliResult<()> {
    match cmd {
        CatalogCommands::Categories(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_catalog_categories(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.categories.is_empty() {
                println!("No catalog categories found.");
            } else {
                println!("{:<38} {:<30}", "ID", "NAME");
                println!("{}", "-".repeat(70));
                for cat in &response.categories {
                    println!("{:<38} {:<30}", cat.id, truncate(&cat.name, 28));
                }
                println!(
                    "\nShowing {} of {} categories",
                    response.categories.len(),
                    response.total
                );
            }
            Ok(())
        }
        CatalogCommands::Items(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_catalog_items(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.items.is_empty() {
                println!("No catalog items found.");
            } else {
                print_catalog_item_table(&response.items);
                println!(
                    "\nShowing {} of {} items",
                    response.items.len(),
                    response.total
                );
            }
            Ok(())
        }
        CatalogCommands::GetItem(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let item = client.get_catalog_item(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&item)?);
            } else {
                print_catalog_item_details(&item);
            }
            Ok(())
        }
    }
}

// --- Bulk Actions execution ---

async fn execute_bulk_actions(cmd: BulkActionsCommands) -> CliResult<()> {
    match cmd {
        BulkActionsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_bulk_actions(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.bulk_actions.is_empty() {
                println!("No bulk actions found.");
            } else {
                print_bulk_action_table(&response.bulk_actions);
                println!(
                    "\nShowing {} of {} bulk actions",
                    response.bulk_actions.len(),
                    response.total
                );
            }
            Ok(())
        }
        BulkActionsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let action = client.get_bulk_action(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&action)?);
            } else {
                print_bulk_action_details(&action);
            }
            Ok(())
        }
    }
}

// --- Delegations execution ---

async fn execute_delegations(cmd: DelegationsCommands) -> CliResult<()> {
    match cmd {
        DelegationsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_delegations(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.delegations.is_empty() {
                println!("No delegations found.");
            } else {
                print_delegation_table(&response.delegations);
                println!(
                    "\nShowing {} of {} delegations",
                    response.delegations.len(),
                    response.total
                );
            }
            Ok(())
        }
        DelegationsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let delegation = client.get_delegation(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&delegation)?);
            } else {
                print_delegation_details(&delegation);
            }
            Ok(())
        }
        DelegationsCommands::Revoke(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.revoke_delegation(id).await?;
            println!("Delegation revoked.");
            Ok(())
        }
    }
}

// --- GDPR execution ---

async fn execute_gdpr(cmd: GdprCommands) -> CliResult<()> {
    match cmd {
        GdprCommands::Report => {
            let client = ApiClient::from_defaults()?;
            let report = client.get_gdpr_report().await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

// --- Risk execution ---

async fn execute_risk(cmd: RiskCommands) -> CliResult<()> {
    match cmd {
        RiskCommands::Score(a) => {
            let user_id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let score = client.get_user_risk_score(user_id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&score)?);
            } else {
                println!("Risk Score for user {}", user_id);
                println!("{}", "\u{2501}".repeat(50));
                println!("Score:      {:.1}", score.score);
                if let Some(ref level) = score.risk_level {
                    println!("Level:      {level}");
                }
                println!(
                    "Calculated: {}",
                    score.calculated_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
            Ok(())
        }
        RiskCommands::Alerts(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_risk_alerts(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.alerts.is_empty() {
                println!("No risk alerts found.");
            } else {
                print_risk_alert_table(&response.alerts);
                println!(
                    "\nShowing {} of {} alerts",
                    response.alerts.len(),
                    response.total
                );
            }
            Ok(())
        }
        RiskCommands::Acknowledge(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.acknowledge_risk_alert(id).await?;
            println!("Risk alert acknowledged.");
            Ok(())
        }
    }
}

// --- Reports execution ---

async fn execute_reports(cmd: ReportsCommands) -> CliResult<()> {
    match cmd {
        ReportsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_reports(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.reports.is_empty() {
                println!("No reports found.");
            } else {
                print_report_table(&response.reports);
                println!(
                    "\nShowing {} of {} reports",
                    response.reports.len(),
                    response.total
                );
            }
            Ok(())
        }
        ReportsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let report = client.get_report(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report_details(&report);
            }
            Ok(())
        }
    }
}

// --- Workflows execution ---

async fn execute_workflows(cmd: WorkflowsCommands) -> CliResult<()> {
    match cmd {
        WorkflowsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_approval_workflows(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.workflows.is_empty() {
                println!("No approval workflows found.");
            } else {
                println!("{:<38} {:<25} {:<10}", "ID", "NAME", "DEFAULT");
                println!("{}", "-".repeat(75));
                for wf in &response.workflows {
                    println!(
                        "{:<38} {:<25} {:<10}",
                        wf.id,
                        truncate(&wf.name, 23),
                        if wf.is_default { "yes" } else { "no" }
                    );
                }
                println!(
                    "\nShowing {} of {} workflows",
                    response.workflows.len(),
                    response.total
                );
            }
            Ok(())
        }
        WorkflowsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let wf = client.get_approval_workflow(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&wf)?);
            } else {
                println!("Approval Workflow: {}", wf.name);
                println!("{}", "\u{2501}".repeat(50));
                println!("ID:          {}", wf.id);
                println!("Name:        {}", wf.name);
                if let Some(ref desc) = wf.description {
                    println!("Description: {desc}");
                }
                println!("Default:     {}", if wf.is_default { "Yes" } else { "No" });
                println!(
                    "Created:     {}",
                    wf.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
            Ok(())
        }
    }
}

// =================================================================
// Helpers
// =================================================================

fn parse_uuid(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str)
        .map_err(|_| CliError::Validation(format!("Invalid ID '{id_str}'. Must be a valid UUID.")))
}

fn print_role_table(roles: &[RoleResponse]) {
    println!(
        "{:<38} {:<25} {:<15} {:<12} {:<10}",
        "ID", "NAME", "TYPE", "RISK", "REQUESTABLE"
    );
    println!("{}", "-".repeat(102));
    for role in roles {
        println!(
            "{:<38} {:<25} {:<15} {:<12} {:<10}",
            role.id,
            truncate(&role.name, 23),
            role.role_type.as_deref().unwrap_or("-"),
            role.risk_level.as_deref().unwrap_or("-"),
            if role.is_requestable { "yes" } else { "no" }
        );
    }
}

fn print_role_details(role: &RoleResponse) {
    println!("Role: {}", role.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", role.id);
    println!("Name:        {}", role.name);
    if let Some(ref desc) = role.description {
        println!("Description: {desc}");
    }
    if let Some(ref rtype) = role.role_type {
        println!("Type:        {rtype}");
    }
    if let Some(ref risk) = role.risk_level {
        println!("Risk Level:  {risk}");
    }
    println!(
        "Requestable: {}",
        if role.is_requestable { "Yes" } else { "No" }
    );
    println!(
        "Created:     {}",
        role.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_entitlement_table(ents: &[EntitlementResponse]) {
    println!("{:<38} {:<25} {:<15} {:<12}", "ID", "NAME", "TYPE", "RISK");
    println!("{}", "-".repeat(92));
    for ent in ents {
        println!(
            "{:<38} {:<25} {:<15} {:<12}",
            ent.id,
            truncate(&ent.name, 23),
            ent.entitlement_type.as_deref().unwrap_or("-"),
            ent.risk_level.as_deref().unwrap_or("-")
        );
    }
}

fn print_entitlement_details(ent: &EntitlementResponse) {
    println!("Entitlement: {}", ent.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", ent.id);
    println!("Name:        {}", ent.name);
    if let Some(ref desc) = ent.description {
        println!("Description: {desc}");
    }
    if let Some(ref etype) = ent.entitlement_type {
        println!("Type:        {etype}");
    }
    if let Some(ref risk) = ent.risk_level {
        println!("Risk Level:  {risk}");
    }
    println!(
        "Created:     {}",
        ent.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_ar_table(ars: &[AccessRequestResponse]) {
    println!(
        "{:<38} {:<15} {:<12} {:<24}",
        "ID", "TYPE", "STATUS", "CREATED"
    );
    println!("{}", "-".repeat(91));
    for ar in ars {
        println!(
            "{:<38} {:<15} {:<12} {:<24}",
            ar.id,
            ar.request_type.as_deref().unwrap_or("-"),
            ar.status,
            ar.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}

fn print_ar_details(ar: &AccessRequestResponse) {
    println!("Access Request: {}", ar.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", ar.id);
    println!("Status:      {}", ar.status);
    if let Some(ref rtype) = ar.request_type {
        println!("Type:        {rtype}");
    }
    if let Some(ref requester) = ar.requester_id {
        println!("Requester:   {requester}");
    }
    if let Some(ref target) = ar.target_id {
        println!("Target:      {target}");
    }
    if let Some(ref just) = ar.justification {
        println!("Reason:      {just}");
    }
    println!(
        "Created:     {}",
        ar.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_archetype_table(archetypes: &[ArchetypeResponse]) {
    println!(
        "{:<38} {:<25} {:<10} {:<24}",
        "ID", "NAME", "ABSTRACT", "CREATED"
    );
    println!("{}", "-".repeat(99));
    for a in archetypes {
        println!(
            "{:<38} {:<25} {:<10} {:<24}",
            a.id,
            truncate(&a.name, 23),
            if a.is_abstract { "yes" } else { "no" },
            a.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}

fn print_archetype_details(a: &ArchetypeResponse) {
    println!("Archetype: {}", a.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", a.id);
    println!("Name:        {}", a.name);
    if let Some(ref desc) = a.description {
        println!("Description: {desc}");
    }
    if let Some(ref parent) = a.parent_id {
        println!("Parent:      {parent}");
    }
    println!("Abstract:    {}", if a.is_abstract { "Yes" } else { "No" });
    println!(
        "Created:     {}",
        a.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_lifecycle_table(configs: &[LifecycleConfigResponse]) {
    println!(
        "{:<38} {:<25} {:<15} {:<8}",
        "ID", "NAME", "OBJECT TYPE", "ACTIVE"
    );
    println!("{}", "-".repeat(88));
    for c in configs {
        println!(
            "{:<38} {:<25} {:<15} {:<8}",
            c.id,
            truncate(&c.name, 23),
            c.object_type.as_deref().unwrap_or("-"),
            if c.is_active { "yes" } else { "no" }
        );
    }
}

fn print_lifecycle_details(c: &LifecycleConfigResponse) {
    println!("Lifecycle Config: {}", c.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", c.id);
    println!("Name:        {}", c.name);
    if let Some(ref desc) = c.description {
        println!("Description: {desc}");
    }
    if let Some(ref otype) = c.object_type {
        println!("Object Type: {otype}");
    }
    println!("Active:      {}", if c.is_active { "Yes" } else { "No" });
    println!(
        "Created:     {}",
        c.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_sod_rule_table(rules: &[SodRuleResponse]) {
    println!(
        "{:<38} {:<25} {:<12} {:<10} {:<8}",
        "ID", "NAME", "TYPE", "SEVERITY", "ENABLED"
    );
    println!("{}", "-".repeat(95));
    for r in rules {
        println!(
            "{:<38} {:<25} {:<12} {:<10} {:<8}",
            r.id,
            truncate(&r.name, 23),
            r.rule_type.as_deref().unwrap_or("-"),
            r.severity.as_deref().unwrap_or("-"),
            if r.is_enabled { "yes" } else { "no" }
        );
    }
}

fn print_sod_rule_details(r: &SodRuleResponse) {
    println!("SoD Rule: {}", r.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", r.id);
    println!("Name:        {}", r.name);
    if let Some(ref desc) = r.description {
        println!("Description: {desc}");
    }
    if let Some(ref rtype) = r.rule_type {
        println!("Type:        {rtype}");
    }
    if let Some(ref sev) = r.severity {
        println!("Severity:    {sev}");
    }
    println!("Enabled:     {}", if r.is_enabled { "Yes" } else { "No" });
    println!(
        "Created:     {}",
        r.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_violation_table(violations: &[SodViolationResponse]) {
    println!(
        "{:<38} {:<38} {:<12} {:<10}",
        "ID", "RULE ID", "STATUS", "SEVERITY"
    );
    println!("{}", "-".repeat(100));
    for v in violations {
        println!(
            "{:<38} {:<38} {:<12} {:<10}",
            v.id,
            v.rule_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            v.status,
            v.severity.as_deref().unwrap_or("-")
        );
    }
}

fn print_campaign_table(campaigns: &[CampaignResponse]) {
    println!(
        "{:<38} {:<25} {:<12} {:<15}",
        "ID", "NAME", "STATUS", "TYPE"
    );
    println!("{}", "-".repeat(92));
    for c in campaigns {
        println!(
            "{:<38} {:<25} {:<12} {:<15}",
            c.id,
            truncate(&c.name, 23),
            c.status,
            c.campaign_type.as_deref().unwrap_or("-")
        );
    }
}

fn print_campaign_details(c: &CampaignResponse) {
    println!("Campaign: {}", c.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", c.id);
    println!("Name:        {}", c.name);
    if let Some(ref desc) = c.description {
        println!("Description: {desc}");
    }
    println!("Status:      {}", c.status);
    if let Some(ref ctype) = c.campaign_type {
        println!("Type:        {ctype}");
    }
    println!(
        "Created:     {}",
        c.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_template_table(templates: &[ObjectTemplateResponse]) {
    println!(
        "{:<38} {:<25} {:<15} {:<8}",
        "ID", "NAME", "OBJECT TYPE", "ACTIVE"
    );
    println!("{}", "-".repeat(88));
    for t in templates {
        println!(
            "{:<38} {:<25} {:<15} {:<8}",
            t.id,
            truncate(&t.name, 23),
            t.object_type.as_deref().unwrap_or("-"),
            if t.is_active { "yes" } else { "no" }
        );
    }
}

fn print_template_details(t: &ObjectTemplateResponse) {
    println!("Object Template: {}", t.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", t.id);
    println!("Name:        {}", t.name);
    if let Some(ref desc) = t.description {
        println!("Description: {desc}");
    }
    if let Some(ref otype) = t.object_type {
        println!("Object Type: {otype}");
    }
    println!("Active:      {}", if t.is_active { "Yes" } else { "No" });
    println!(
        "Created:     {}",
        t.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_catalog_item_table(items: &[CatalogItemResponse]) {
    println!(
        "{:<38} {:<25} {:<8} {:<24}",
        "ID", "NAME", "ENABLED", "CREATED"
    );
    println!("{}", "-".repeat(97));
    for item in items {
        println!(
            "{:<38} {:<25} {:<8} {:<24}",
            item.id,
            truncate(&item.name, 23),
            if item.is_enabled { "yes" } else { "no" },
            item.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}

fn print_catalog_item_details(item: &CatalogItemResponse) {
    println!("Catalog Item: {}", item.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", item.id);
    println!("Name:        {}", item.name);
    if let Some(ref desc) = item.description {
        println!("Description: {desc}");
    }
    if let Some(ref cat) = item.category_id {
        println!("Category:    {cat}");
    }
    println!(
        "Enabled:     {}",
        if item.is_enabled { "Yes" } else { "No" }
    );
    println!(
        "Created:     {}",
        item.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_bulk_action_table(actions: &[BulkActionResponse]) {
    println!(
        "{:<38} {:<15} {:<12} {:<10} {:<10}",
        "ID", "TYPE", "STATUS", "TOTAL", "DONE"
    );
    println!("{}", "-".repeat(87));
    for a in actions {
        println!(
            "{:<38} {:<15} {:<12} {:<10} {:<10}",
            a.id,
            a.action_type.as_deref().unwrap_or("-"),
            a.status,
            a.total_items.unwrap_or(0),
            a.processed_items.unwrap_or(0)
        );
    }
}

fn print_bulk_action_details(a: &BulkActionResponse) {
    println!("Bulk Action: {}", a.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", a.id);
    if let Some(ref atype) = a.action_type {
        println!("Type:        {atype}");
    }
    println!("Status:      {}", a.status);
    if let Some(total) = a.total_items {
        println!("Total:       {total}");
    }
    if let Some(done) = a.processed_items {
        println!("Processed:   {done}");
    }
    println!(
        "Created:     {}",
        a.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_delegation_table(delegations: &[DelegationResponse]) {
    println!(
        "{:<38} {:<38} {:<12} {:<24}",
        "ID", "DEPUTY", "STATUS", "CREATED"
    );
    println!("{}", "-".repeat(114));
    for d in delegations {
        println!(
            "{:<38} {:<38} {:<12} {:<24}",
            d.id,
            d.deputy_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            d.status,
            d.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}

fn print_delegation_details(d: &DelegationResponse) {
    println!("Delegation: {}", d.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", d.id);
    if let Some(ref delegator) = d.delegator_id {
        println!("Delegator:   {delegator}");
    }
    if let Some(ref deputy) = d.deputy_id {
        println!("Deputy:      {deputy}");
    }
    println!("Status:      {}", d.status);
    if let Some(ref starts) = d.starts_at {
        println!("Starts:      {}", starts.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    if let Some(ref ends) = d.ends_at {
        println!("Ends:        {}", ends.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    println!(
        "Created:     {}",
        d.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}

fn print_risk_alert_table(alerts: &[RiskAlertResponse]) {
    println!(
        "{:<38} {:<12} {:<10} {:<12} {:<24}",
        "ID", "TYPE", "SEVERITY", "STATUS", "CREATED"
    );
    println!("{}", "-".repeat(98));
    for a in alerts {
        println!(
            "{:<38} {:<12} {:<10} {:<12} {:<24}",
            a.id,
            a.alert_type.as_deref().unwrap_or("-"),
            a.severity.as_deref().unwrap_or("-"),
            a.status,
            a.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}

fn print_report_table(reports: &[ReportResponse]) {
    println!(
        "{:<38} {:<25} {:<12} {:<10}",
        "ID", "NAME", "STATUS", "FORMAT"
    );
    println!("{}", "-".repeat(87));
    for r in reports {
        println!(
            "{:<38} {:<25} {:<12} {:<10}",
            r.id,
            truncate(&r.name, 23),
            r.status,
            r.format.as_deref().unwrap_or("-")
        );
    }
}

fn print_report_details(r: &ReportResponse) {
    println!("Report: {}", r.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", r.id);
    println!("Name:        {}", r.name);
    if let Some(ref rtype) = r.report_type {
        println!("Type:        {rtype}");
    }
    println!("Status:      {}", r.status);
    if let Some(ref fmt) = r.format {
        println!("Format:      {fmt}");
    }
    println!(
        "Created:     {}",
        r.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}
