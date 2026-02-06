//! Connector management CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::connector::{ConnectorResponse, CreateConnectorRequest};
use crate::output::{truncate, validate_pagination};
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// Connector management commands
#[derive(Args, Debug)]
pub struct ConnectorsArgs {
    #[command(subcommand)]
    pub command: ConnectorsCommands,
}

#[derive(Subcommand, Debug)]
pub enum ConnectorsCommands {
    /// List all connectors
    List(ListArgs),
    /// Get details of a specific connector
    Get(GetArgs),
    /// Create a new connector
    Create(CreateArgs),
    /// Delete a connector
    Delete(DeleteArgs),
    /// Test a connector's connectivity
    Test(TestArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
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
    /// Connector name
    pub name: String,

    /// Connector type (e.g., ldap, rest, database, scim, entra)
    #[arg(long, short = 't')]
    pub connector_type: String,

    /// Description
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// Configuration JSON
    #[arg(long)]
    pub config: Option<String>,

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
pub struct TestArgs {
    pub id: String,
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: ConnectorsArgs) -> CliResult<()> {
    match args.command {
        ConnectorsCommands::List(a) => execute_list(a).await,
        ConnectorsCommands::Get(a) => execute_get(a).await,
        ConnectorsCommands::Create(a) => execute_create(a).await,
        ConnectorsCommands::Delete(a) => execute_delete(a).await,
        ConnectorsCommands::Test(a) => execute_test(a).await,
    }
}

async fn execute_list(args: ListArgs) -> CliResult<()> {
    validate_pagination(args.limit, args.offset)?;
    let client = ApiClient::from_defaults()?;

    let response = client.list_connectors(args.limit, args.offset).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.connectors.is_empty() {
        println!("No connectors found.");
    } else {
        print_connector_table(&response.connectors);
        println!();
        println!(
            "Showing {} of {} connectors",
            response.connectors.len(),
            response.total
        );
    }

    Ok(())
}

async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let conn = client.get_connector(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&conn)?);
    } else {
        print_connector_details(&conn);
    }

    Ok(())
}

async fn execute_create(args: CreateArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let cfg = args
        .config
        .map(|c| serde_json::from_str(&c))
        .transpose()
        .map_err(|e| CliError::Validation(format!("Invalid config JSON: {e}")))?;

    let request = CreateConnectorRequest {
        name: args.name,
        connector_type: args.connector_type,
        description: args.description,
        config: cfg,
    };

    let conn = client.create_connector(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&conn)?);
    } else {
        println!("Connector created successfully!");
        println!();
        print_connector_details(&conn);
    }

    Ok(())
}

async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let conn = client.get_connector(id).await?;

    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Use --force in non-interactive mode.".to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt(format!("Delete connector '{}'?", conn.name))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    client.delete_connector(id).await?;
    println!("Connector deleted: {}", conn.name);

    Ok(())
}

async fn execute_test(args: TestArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let result = client.test_connector(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Connector test result:");
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

fn parse_uuid(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str)
        .map_err(|_| CliError::Validation(format!("Invalid ID '{id_str}'. Must be a valid UUID.")))
}

fn print_connector_table(conns: &[ConnectorResponse]) {
    println!(
        "{:<38} {:<20} {:<12} {:<10} {:<8}",
        "ID", "NAME", "TYPE", "STATUS", "ACTIVE"
    );
    println!("{}", "-".repeat(90));

    for conn in conns {
        let name = truncate(&conn.name, 18);
        let ctype = conn.connector_type.as_deref().unwrap_or("-");
        println!(
            "{:<38} {:<20} {:<12} {:<10} {:<8}",
            conn.id,
            name,
            ctype,
            conn.status,
            if conn.is_active { "yes" } else { "no" }
        );
    }
}

fn print_connector_details(conn: &ConnectorResponse) {
    println!("Connector: {}", conn.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:     {}", conn.id);
    println!("Name:   {}", conn.name);
    if let Some(ref ctype) = conn.connector_type {
        println!("Type:   {ctype}");
    }
    println!("Status: {}", conn.status);
    println!("Active: {}", if conn.is_active { "Yes" } else { "No" });
    if let Some(ref desc) = conn.description {
        println!("Desc:   {desc}");
    }
    println!(
        "Created: {}",
        conn.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}
