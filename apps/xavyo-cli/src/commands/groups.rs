//! Group management CLI commands

use crate::api::ApiClient;
use crate::error::CliResult;
use crate::models::group::GroupResponse;
use crate::output::{truncate, validate_pagination};
use clap::{Args, Subcommand};

/// Group management commands
#[derive(Args, Debug)]
pub struct GroupsArgs {
    #[command(subcommand)]
    pub command: GroupsCommands,
}

#[derive(Subcommand, Debug)]
pub enum GroupsCommands {
    /// List all groups in the current tenant
    List(ListArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Maximum number of groups to return
    #[arg(long, default_value = "50")]
    pub limit: i32,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: i32,
}

/// Execute group commands
pub async fn execute(args: GroupsArgs) -> CliResult<()> {
    match args.command {
        GroupsCommands::List(a) => execute_list(a).await,
    }
}

async fn execute_list(args: ListArgs) -> CliResult<()> {
    validate_pagination(args.limit, args.offset)?;
    let client = ApiClient::from_defaults()?;

    let response = client.list_groups(args.limit, args.offset).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.groups.is_empty() {
        println!("No groups found.");
    } else {
        print_group_table(&response.groups);
        println!();
        println!(
            "Showing {} of {} groups",
            response.groups.len(),
            response.total
        );
    }

    Ok(())
}

fn print_group_table(groups: &[GroupResponse]) {
    println!(
        "{:<38} {:<25} {:<15} {:<10}",
        "ID", "DISPLAY NAME", "TYPE", "MEMBERS"
    );
    println!("{}", "-".repeat(90));

    for group in groups {
        let display = truncate(&group.display_name, 23);
        let gtype = group.group_type.as_deref().unwrap_or("-");
        let members = group
            .member_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".to_string());

        println!(
            "{:<38} {:<25} {:<15} {:<10}",
            group.id, display, gtype, members
        );
    }
}
