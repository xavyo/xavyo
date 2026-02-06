//! Identity provider management CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::identity_provider::{CreateIdentityProviderRequest, IdentityProviderResponse};
use crate::output::{truncate, validate_pagination};
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// Identity provider management commands
#[derive(Args, Debug)]
pub struct IdentityProvidersArgs {
    #[command(subcommand)]
    pub command: IdentityProvidersCommands,
}

#[derive(Subcommand, Debug)]
pub enum IdentityProvidersCommands {
    /// List all identity providers
    List(ListArgs),
    /// Get details of a specific identity provider
    Get(GetArgs),
    /// Create a new identity provider
    Create(CreateArgs),
    /// Delete an identity provider
    Delete(DeleteArgs),
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
    /// Provider name
    pub name: String,

    /// Provider type (oidc, saml)
    #[arg(long, short = 't')]
    pub provider_type: String,

    /// Issuer URL (for OIDC providers)
    #[arg(long)]
    pub issuer_url: Option<String>,

    /// Client ID
    #[arg(long)]
    pub client_id: Option<String>,

    /// Client secret
    #[arg(long)]
    pub client_secret: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    pub id: String,
    #[arg(long, short = 'f')]
    pub force: bool,
}

pub async fn execute(args: IdentityProvidersArgs) -> CliResult<()> {
    match args.command {
        IdentityProvidersCommands::List(a) => execute_list(a).await,
        IdentityProvidersCommands::Get(a) => execute_get(a).await,
        IdentityProvidersCommands::Create(a) => execute_create(a).await,
        IdentityProvidersCommands::Delete(a) => execute_delete(a).await,
    }
}

async fn execute_list(args: ListArgs) -> CliResult<()> {
    validate_pagination(args.limit, args.offset)?;
    let client = ApiClient::from_defaults()?;

    let response = client
        .list_identity_providers(args.limit, args.offset)
        .await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.identity_providers.is_empty() {
        println!("No identity providers found.");
    } else {
        print_idp_table(&response.identity_providers);
        println!();
        println!(
            "Showing {} of {} identity providers",
            response.identity_providers.len(),
            response.total
        );
    }

    Ok(())
}

async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let idp = client.get_identity_provider(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&idp)?);
    } else {
        print_idp_details(&idp);
    }

    Ok(())
}

async fn execute_create(args: CreateArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let request = CreateIdentityProviderRequest {
        name: args.name,
        provider_type: args.provider_type,
        issuer_url: args.issuer_url,
        client_id: args.client_id,
        client_secret: args.client_secret,
    };

    let idp = client.create_identity_provider(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&idp)?);
    } else {
        println!("Identity provider created successfully!");
        println!();
        print_idp_details(&idp);
    }

    Ok(())
}

async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let idp = client.get_identity_provider(id).await?;

    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Use --force in non-interactive mode.".to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt(format!("Delete identity provider '{}'?", idp.name))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    client.delete_identity_provider(id).await?;
    println!("Identity provider deleted: {}", idp.name);

    Ok(())
}

fn parse_uuid(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str)
        .map_err(|_| CliError::Validation(format!("Invalid ID '{id_str}'. Must be a valid UUID.")))
}

fn print_idp_table(idps: &[IdentityProviderResponse]) {
    println!(
        "{:<38} {:<25} {:<10} {:<10} {:<10}",
        "ID", "NAME", "TYPE", "ENABLED", "VALIDATED"
    );
    println!("{}", "-".repeat(95));

    for idp in idps {
        let name = truncate(&idp.name, 23);
        let ptype = idp.provider_type.as_deref().unwrap_or("-");
        println!(
            "{:<38} {:<25} {:<10} {:<10} {:<10}",
            idp.id,
            name,
            ptype,
            if idp.is_enabled { "yes" } else { "no" },
            if idp.is_validated { "yes" } else { "no" }
        );
    }
}

fn print_idp_details(idp: &IdentityProviderResponse) {
    println!("Identity Provider: {}", idp.name);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:        {}", idp.id);
    println!("Name:      {}", idp.name);
    if let Some(ref ptype) = idp.provider_type {
        println!("Type:      {ptype}");
    }
    if let Some(ref issuer) = idp.issuer_url {
        println!("Issuer:    {issuer}");
    }
    println!("Enabled:   {}", if idp.is_enabled { "Yes" } else { "No" });
    println!("Validated: {}", if idp.is_validated { "Yes" } else { "No" });
    println!(
        "Created:   {}",
        idp.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
}
