//! Service account management CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::service_account::{
    CreateServiceAccountRequest, ServiceAccountResponse, UpdateServiceAccountRequest,
};
use crate::output::{truncate, validate_pagination};
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// Service account management commands
#[derive(Args, Debug)]
pub struct ServiceAccountsArgs {
    #[command(subcommand)]
    pub command: ServiceAccountsCommands,
}

#[derive(Subcommand, Debug)]
pub enum ServiceAccountsCommands {
    /// List all service accounts
    List(ListArgs),
    /// Get details of a specific service account
    Get(GetArgs),
    /// Create a new service account
    Create(CreateArgs),
    /// Update a service account
    Update(UpdateArgs),
    /// Delete a service account
    Delete(DeleteArgs),
    /// Suspend a service account
    Suspend(IdArgs),
    /// Reactivate a service account
    Reactivate(IdArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    #[arg(long, default_value = "50")]
    pub limit: i32,

    #[arg(long, default_value = "0")]
    pub offset: i32,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    pub id: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Service account name
    pub name: String,

    /// Description
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// Owner user ID
    #[arg(long)]
    pub owner_id: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct UpdateArgs {
    pub id: String,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long, short = 'd')]
    pub description: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    pub id: String,

    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct IdArgs {
    pub id: String,
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: ServiceAccountsArgs) -> CliResult<()> {
    match args.command {
        ServiceAccountsCommands::List(a) => execute_list(a).await,
        ServiceAccountsCommands::Get(a) => execute_get(a).await,
        ServiceAccountsCommands::Create(a) => execute_create(a).await,
        ServiceAccountsCommands::Update(a) => execute_update(a).await,
        ServiceAccountsCommands::Delete(a) => execute_delete(a).await,
        ServiceAccountsCommands::Suspend(a) => execute_suspend(a).await,
        ServiceAccountsCommands::Reactivate(a) => execute_reactivate(a).await,
    }
}

async fn execute_list(args: ListArgs) -> CliResult<()> {
    validate_pagination(args.limit, args.offset)?;
    let client = ApiClient::from_defaults()?;

    let response = client
        .list_service_accounts(args.limit, args.offset)
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.items.is_empty() {
        println!("No service accounts found.");
    } else {
        print_sa_table(&response.items);
        println!();
        println!(
            "Showing {} of {} service accounts",
            response.items.len(),
            response.total
        );
    }

    Ok(())
}

async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let sa = client.get_service_account(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&sa)?);
    } else {
        print_sa_details(&sa);
    }

    Ok(())
}

async fn execute_create(args: CreateArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let owner_id = args.owner_id.map(|o| parse_uuid(&o)).transpose()?;

    let request = CreateServiceAccountRequest {
        name: args.name,
        description: args.description,
        owner_id,
    };

    let sa = client.create_service_account(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&sa)?);
    } else {
        println!("Service account created successfully!");
        println!();
        print_sa_details(&sa);
    }

    Ok(())
}

async fn execute_update(args: UpdateArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let request = UpdateServiceAccountRequest {
        name: args.name,
        description: args.description,
    };

    let sa = client.update_service_account(id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&sa)?);
    } else {
        println!("Service account updated successfully!");
        println!();
        print_sa_details(&sa);
    }

    Ok(())
}

async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let sa = client.get_service_account(id).await?;

    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Use --force in non-interactive mode.".to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt(format!("Delete service account '{}'?", sa.name))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    client.delete_service_account(id).await?;
    println!("Service account deleted: {}", sa.name);

    Ok(())
}

async fn execute_suspend(args: IdArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let sa = client.suspend_service_account(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&sa)?);
    } else {
        println!("Service account suspended: {}", sa.name);
    }

    Ok(())
}

async fn execute_reactivate(args: IdArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let sa = client.reactivate_service_account(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&sa)?);
    } else {
        println!("Service account reactivated: {}", sa.name);
    }

    Ok(())
}

fn parse_uuid(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str)
        .map_err(|_| CliError::Validation(format!("Invalid ID '{id_str}'. Must be a valid UUID.")))
}

fn print_sa_table(sas: &[ServiceAccountResponse]) {
    println!(
        "{:<38} {:<25} {:<12} {:<15}",
        "ID", "NAME", "STATUS", "RISK LEVEL"
    );
    println!("{}", "-".repeat(92));

    for sa in sas {
        let name = truncate(&sa.name, 23);
        let risk = sa.risk_level.as_deref().unwrap_or("-");
        println!("{:<38} {:<25} {:<12} {:<15}", sa.id, name, sa.status, risk);
    }
}

fn print_sa_details(sa: &ServiceAccountResponse) {
    println!("Service Account: {}", sa.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", sa.id);
    println!("Name:        {}", sa.name);
    println!("Status:      {}", sa.status);

    if let Some(ref desc) = sa.description {
        println!("Description: {desc}");
    }
    if let Some(ref risk) = sa.risk_level {
        println!("Risk Level:  {risk}");
    }
    if let Some(ref owner) = sa.owner_id {
        println!("Owner:       {owner}");
    }

    println!(
        "Created:     {}",
        sa.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(ref updated) = sa.updated_at {
        println!("Updated:     {}", updated.format("%Y-%m-%d %H:%M:%S UTC"));
    }
}
