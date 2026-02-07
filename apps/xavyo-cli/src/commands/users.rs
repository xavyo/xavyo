//! User management CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::user::{CreateUserRequest, UpdateUserRequest, UserResponse};
use crate::output::{parse_comma_list, truncate, validate_pagination};
use clap::{Args, Subcommand};
use dialoguer::Confirm;
use uuid::Uuid;

/// User management commands
#[derive(Args, Debug)]
pub struct UsersArgs {
    #[command(subcommand)]
    pub command: UsersCommands,
}

#[derive(Subcommand, Debug)]
pub enum UsersCommands {
    /// List all users in the current tenant
    List(ListArgs),
    /// Get details of a specific user
    Get(GetArgs),
    /// Create a new user
    Create(CreateArgs),
    /// Update an existing user
    Update(UpdateArgs),
    /// Deactivate a user
    Delete(DeleteArgs),
}

/// Arguments for the list command
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Maximum number of users to return (1-100)
    #[arg(long, default_value = "50")]
    pub limit: i32,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: i32,
}

/// Arguments for the get command
#[derive(Args, Debug)]
pub struct GetArgs {
    /// User ID (UUID)
    pub id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the create command
#[derive(Args, Debug)]
pub struct CreateArgs {
    /// User email address
    pub email: String,

    /// Display name
    #[arg(long)]
    pub display_name: Option<String>,

    /// First name
    #[arg(long)]
    pub first_name: Option<String>,

    /// Last name
    #[arg(long)]
    pub last_name: Option<String>,

    /// Password (if not provided, user must set via email)
    #[arg(long)]
    pub password: Option<String>,

    /// Roles to assign (comma-separated)
    #[arg(long)]
    pub roles: Option<String>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the update command
#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// User ID (UUID)
    pub id: String,

    /// Display name
    #[arg(long)]
    pub display_name: Option<String>,

    /// First name
    #[arg(long)]
    pub first_name: Option<String>,

    /// Last name
    #[arg(long)]
    pub last_name: Option<String>,

    /// Set active status (true/false)
    #[arg(long)]
    pub active: Option<bool>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the delete command
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// User ID (UUID)
    pub id: String,

    /// Skip confirmation prompt
    #[arg(long, short = 'f')]
    pub force: bool,
}

/// Execute user commands
pub async fn execute(args: UsersArgs) -> CliResult<()> {
    match args.command {
        UsersCommands::List(a) => execute_list(a).await,
        UsersCommands::Get(a) => execute_get(a).await,
        UsersCommands::Create(a) => execute_create(a).await,
        UsersCommands::Update(a) => execute_update(a).await,
        UsersCommands::Delete(a) => execute_delete(a).await,
    }
}

async fn execute_list(args: ListArgs) -> CliResult<()> {
    validate_pagination(args.limit, args.offset)?;
    let client = ApiClient::from_defaults()?;

    let response = client.list_users(args.limit, args.offset).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.users.is_empty() {
        println!("No users found.");
    } else {
        print_user_table(&response.users);
        let total = response
            .pagination
            .as_ref()
            .and_then(|p| p.total_count)
            .unwrap_or(response.users.len() as i64);
        println!("\nShowing {} of {} users", response.users.len(), total);
    }

    Ok(())
}

async fn execute_get(args: GetArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id, "user")?;
    let client = ApiClient::from_defaults()?;

    let user = client.get_user(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&user)?);
    } else {
        print_user_details(&user);
    }

    Ok(())
}

async fn execute_create(args: CreateArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;

    let roles = args.roles.as_deref().map(parse_comma_list);

    let request = CreateUserRequest {
        email: args.email,
        display_name: args.display_name,
        first_name: args.first_name,
        last_name: args.last_name,
        password: args.password,
        roles,
    };

    let user = client.create_user(request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&user)?);
    } else {
        println!("User created successfully!");
        println!();
        print_user_details(&user);
    }

    Ok(())
}

async fn execute_update(args: UpdateArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id, "user")?;
    let client = ApiClient::from_defaults()?;

    let request = UpdateUserRequest {
        display_name: args.display_name,
        first_name: args.first_name,
        last_name: args.last_name,
        is_active: args.active,
    };

    let user = client.update_user(id, request).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&user)?);
    } else {
        println!("User updated successfully!");
        println!();
        print_user_details(&user);
    }

    Ok(())
}

async fn execute_delete(args: DeleteArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id, "user")?;
    let client = ApiClient::from_defaults()?;

    let user = client.get_user(id).await?;

    if !args.force {
        if !atty::is(atty::Stream::Stdin) {
            return Err(CliError::Validation(
                "Cannot confirm deletion in non-interactive mode. Use --force to skip confirmation."
                    .to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt(format!(
                "Deactivate user '{}'? This will disable their access.",
                user.email
            ))
            .default(false)
            .interact()
            .map_err(|e| CliError::Io(e.to_string()))?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    client.delete_user(id).await?;
    println!("User deactivated: {}", user.email);

    Ok(())
}

fn parse_uuid(id_str: &str, resource: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str).map_err(|_| {
        CliError::Validation(format!(
            "Invalid {resource} ID '{id_str}'. Must be a valid UUID."
        ))
    })
}

fn print_user_table(users: &[UserResponse]) {
    println!(
        "{:<38} {:<30} {:<20} {:<10} {:<8}",
        "ID", "EMAIL", "DISPLAY NAME", "STATUS", "ACTIVE"
    );
    println!("{}", "-".repeat(108));

    for user in users {
        let display = user.display_name.as_deref().unwrap_or("-");

        println!(
            "{:<38} {:<30} {:<20} {:<10} {:<8}",
            user.id,
            truncate(&user.email, 28),
            truncate(display, 18),
            user.status,
            if user.is_active { "yes" } else { "no" }
        );
    }
}

fn print_user_details(user: &UserResponse) {
    println!("User: {}", user.email);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:             {}", user.id);
    println!("Email:          {}", user.email);
    println!(
        "Email Verified: {}",
        if user.email_verified { "Yes" } else { "No" }
    );

    if let Some(ref name) = user.display_name {
        println!("Display Name:   {name}");
    }
    if let Some(ref name) = user.first_name {
        println!("First Name:     {name}");
    }
    if let Some(ref name) = user.last_name {
        println!("Last Name:      {name}");
    }

    println!("Status:         {}", user.status);
    println!(
        "Active:         {}",
        if user.is_active { "Yes" } else { "No" }
    );

    if !user.roles.is_empty() {
        println!("Roles:          {}", user.roles.join(", "));
    }

    println!(
        "Created:        {}",
        user.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Updated:        {}",
        user.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    if let Some(ref last_login) = user.last_login_at {
        println!(
            "Last Login:     {}",
            last_login.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uuid_valid() {
        let valid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        assert!(parse_uuid(valid, "user").is_ok());
    }

    #[test]
    fn test_parse_uuid_invalid() {
        assert!(parse_uuid("not-a-uuid", "user").is_err());
    }
}
