//! Webhook management CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::webhook::{CreateWebhookRequest, UpdateWebhookRequest, WebhookResponse};
use crate::output::{parse_comma_list, truncate, validate_pagination};
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// Webhook management commands
#[derive(Args, Debug)]
pub struct WebhooksArgs {
    #[command(subcommand)]
    pub command: WebhooksCommands,
}

#[derive(Subcommand, Debug)]
pub enum WebhooksCommands {
    /// List all webhook subscriptions
    List(ListArgs),
    /// Get details of a specific webhook subscription
    Get(GetArgs),
    /// Create a new webhook subscription
    Create(CreateArgs),
    /// Update a webhook subscription
    Update(UpdateArgs),
    /// Delete a webhook subscription
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
    /// Webhook URL
    pub url: String,

    /// Events to subscribe to (comma-separated, e.g., user.created,user.updated)
    #[arg(long, short = 'e')]
    pub events: String,

    /// Webhook name
    #[arg(long)]
    pub name: Option<String>,

    /// Signing secret
    #[arg(long)]
    pub secret: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct UpdateArgs {
    pub id: String,

    #[arg(long)]
    pub url: Option<String>,

    #[arg(long, short = 'e')]
    pub events: Option<String>,

    #[arg(long)]
    pub active: Option<bool>,

    #[arg(long)]
    pub name: Option<String>,

    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    pub id: String,
    #[arg(long, short = 'f')]
    pub force: bool,
}

pub async fn execute(args: WebhooksArgs) -> CliResult<()> {
    match args.command {
        WebhooksCommands::List(a) => execute_list(a).await,
        WebhooksCommands::Get(a) => execute_get(a).await,
        WebhooksCommands::Create(a) => execute_create(a).await,
        WebhooksCommands::Update(a) => execute_update(a).await,
        WebhooksCommands::Delete(a) => execute_delete(a).await,
    }
}

async fn execute_list(args: ListArgs) -> CliResult<()> {
    validate_pagination(args.limit, args.offset)?;
    let client = ApiClient::from_defaults()?;

    let response = client.list_webhooks(args.limit, args.offset).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.webhooks.is_empty() {
        println!("No webhooks found.");
    } else {
        print_webhook_table(&response.webhooks);
        println!();
        println!(
            "Showing {} of {} webhooks",
            response.webhooks.len(),
            response.total
        );
    }

    Ok(())
}

async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let webhook = client.get_webhook(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&webhook)?);
    } else {
        print_webhook_details(&webhook);
    }

    Ok(())
}

async fn execute_create(args: CreateArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let events = parse_comma_list(&args.events);

    let request = CreateWebhookRequest {
        url: args.url,
        events,
        name: args.name,
        secret: args.secret,
    };

    let webhook = client.create_webhook(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&webhook)?);
    } else {
        println!("Webhook created successfully!");
        println!();
        print_webhook_details(&webhook);
    }

    Ok(())
}

async fn execute_update(args: UpdateArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let events = args.events.as_deref().map(parse_comma_list);

    let request = UpdateWebhookRequest {
        url: args.url,
        events,
        is_active: args.active,
        name: args.name,
    };

    let webhook = client.update_webhook(id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&webhook)?);
    } else {
        println!("Webhook updated successfully!");
        println!();
        print_webhook_details(&webhook);
    }

    Ok(())
}

async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;

    let webhook = client.get_webhook(id).await?;

    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Use --force in non-interactive mode.".to_string(),
            ));
        }

        let name = webhook.name.as_deref().unwrap_or(&webhook.url);
        let confirm = Confirm::new()
            .with_prompt(format!("Delete webhook '{name}'?"))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    client.delete_webhook(id).await?;
    let name = webhook.name.as_deref().unwrap_or(&webhook.url);
    println!("Webhook deleted: {name}");

    Ok(())
}

fn parse_uuid(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str)
        .map_err(|_| CliError::Validation(format!("Invalid ID '{id_str}'. Must be a valid UUID.")))
}

fn print_webhook_table(webhooks: &[WebhookResponse]) {
    println!("{:<38} {:<20} {:<35} {:<8}", "ID", "NAME", "URL", "ACTIVE");
    println!("{}", "-".repeat(103));

    for wh in webhooks {
        let name = wh.name.as_deref().unwrap_or("-");
        let truncated_name = truncate(name, 18);
        let truncated_url = truncate(&wh.url, 33);

        println!(
            "{:<38} {:<20} {:<35} {:<8}",
            wh.id,
            truncated_name,
            truncated_url,
            if wh.is_active { "yes" } else { "no" }
        );
    }
}

fn print_webhook_details(wh: &WebhookResponse) {
    let name = wh.name.as_deref().unwrap_or(&wh.url);
    println!("Webhook: {name}");
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:     {}", wh.id);
    if let Some(ref n) = wh.name {
        println!("Name:   {n}");
    }
    println!("URL:    {}", wh.url);
    println!("Active: {}", if wh.is_active { "Yes" } else { "No" });
    if !wh.events.is_empty() {
        println!("Events: {}", wh.events.join(", "));
    }
    println!("Created: {}", wh.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
}
