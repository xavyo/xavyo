//! Operations and jobs CLI commands

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::operation::{
    DlqEntryResponse, JobResponse, OperationResponse, QueueStatsResponse,
};
use crate::output::{truncate, validate_pagination};
use clap::{Args, Subcommand};
use uuid::Uuid;

/// Provisioning operations and job tracking
#[derive(Args, Debug)]
pub struct OperationsArgs {
    #[command(subcommand)]
    pub command: OperationsCommands,
}

#[derive(Subcommand, Debug)]
pub enum OperationsCommands {
    /// List provisioning operations
    List(PaginationArgs),
    /// Get a specific operation
    Get(IdJsonArgs),
    /// Get queue statistics
    Stats(StatsArgs),
    /// Retry a failed operation
    Retry(IdOnlyArgs),
    /// Cancel a pending operation
    Cancel(IdOnlyArgs),
    /// Manage connector jobs
    #[command(subcommand)]
    Jobs(JobsCommands),
    /// Dead letter queue management
    #[command(subcommand)]
    Dlq(DlqCommands),
}

#[derive(Subcommand, Debug)]
pub enum JobsCommands {
    /// List connector jobs
    List(PaginationArgs),
    /// Get a specific job
    Get(IdJsonArgs),
    /// Cancel a job
    Cancel(IdOnlyArgs),
}

#[derive(Subcommand, Debug)]
pub enum DlqCommands {
    /// List dead letter queue entries
    List(PaginationArgs),
    /// Replay a DLQ entry
    Replay(IdOnlyArgs),
}

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
pub struct StatsArgs {
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: OperationsArgs) -> CliResult<()> {
    match args.command {
        OperationsCommands::List(a) => execute_list(a).await,
        OperationsCommands::Get(a) => execute_get(a).await,
        OperationsCommands::Stats(a) => execute_stats(a).await,
        OperationsCommands::Retry(a) => execute_retry(a).await,
        OperationsCommands::Cancel(a) => execute_cancel(a).await,
        OperationsCommands::Jobs(cmd) => execute_jobs(cmd).await,
        OperationsCommands::Dlq(cmd) => execute_dlq(cmd).await,
    }
}

async fn execute_list(args: PaginationArgs) -> CliResult<()> {
    validate_pagination(args.limit, args.offset)?;
    let client = ApiClient::from_defaults()?;
    let response = client.list_prov_operations(args.limit, args.offset).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else if response.operations.is_empty() {
        println!("No operations found.");
    } else {
        print_operation_table(&response.operations);
        println!(
            "\nShowing {} of {} operations",
            response.operations.len(),
            response.total
        );
    }
    Ok(())
}

async fn execute_get(args: IdJsonArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;
    let op = client.get_prov_operation(id).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&op)?);
    } else {
        print_operation_details(&op);
    }
    Ok(())
}

async fn execute_stats(args: StatsArgs) -> CliResult<()> {
    let client = ApiClient::from_defaults()?;
    let stats = client.get_queue_stats().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        print_queue_stats(&stats);
    }
    Ok(())
}

async fn execute_retry(args: IdOnlyArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;
    client.retry_prov_operation(id).await?;
    println!("Operation queued for retry.");
    Ok(())
}

async fn execute_cancel(args: IdOnlyArgs) -> CliResult<()> {
    let id = parse_uuid(&args.id)?;
    let client = ApiClient::from_defaults()?;
    client.cancel_prov_operation(id).await?;
    println!("Operation cancelled.");
    Ok(())
}

async fn execute_jobs(cmd: JobsCommands) -> CliResult<()> {
    match cmd {
        JobsCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_jobs(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.jobs.is_empty() {
                println!("No jobs found.");
            } else {
                print_job_table(&response.jobs);
                println!(
                    "\nShowing {} of {} jobs",
                    response.jobs.len(),
                    response.total
                );
            }
            Ok(())
        }
        JobsCommands::Get(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            let job = client.get_job(id).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&job)?);
            } else {
                print_job_details(&job);
            }
            Ok(())
        }
        JobsCommands::Cancel(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.cancel_job(id).await?;
            println!("Job cancelled.");
            Ok(())
        }
    }
}

async fn execute_dlq(cmd: DlqCommands) -> CliResult<()> {
    match cmd {
        DlqCommands::List(a) => {
            validate_pagination(a.limit, a.offset)?;
            let client = ApiClient::from_defaults()?;
            let response = client.list_dlq(a.limit, a.offset).await?;

            if a.json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else if response.entries.is_empty() {
                println!("No dead letter queue entries.");
            } else {
                print_dlq_table(&response.entries);
                println!(
                    "\nShowing {} of {} DLQ entries",
                    response.entries.len(),
                    response.total
                );
            }
            Ok(())
        }
        DlqCommands::Replay(a) => {
            let id = parse_uuid(&a.id)?;
            let client = ApiClient::from_defaults()?;
            client.replay_dlq(id).await?;
            println!("DLQ entry queued for replay.");
            Ok(())
        }
    }
}

// --- Helpers ---

fn parse_uuid(id_str: &str) -> CliResult<Uuid> {
    Uuid::parse_str(id_str)
        .map_err(|_| CliError::Validation(format!("Invalid ID '{id_str}'. Must be a valid UUID.")))
}

fn print_operation_table(ops: &[OperationResponse]) {
    println!(
        "{:<38} {:<15} {:<12} {:<15} {:<24}",
        "ID", "TYPE", "STATUS", "TARGET TYPE", "CREATED"
    );
    println!("{}", "-".repeat(106));
    for op in ops {
        println!(
            "{:<38} {:<15} {:<12} {:<15} {:<24}",
            op.id,
            truncate(op.operation_type.as_deref().unwrap_or("-"), 13),
            op.status,
            op.target_type.as_deref().unwrap_or("-"),
            op.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}

fn print_operation_details(op: &OperationResponse) {
    println!("Operation: {}", op.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", op.id);
    if let Some(ref otype) = op.operation_type {
        println!("Type:        {otype}");
    }
    println!("Status:      {}", op.status);
    if let Some(ref ttype) = op.target_type {
        println!("Target Type: {ttype}");
    }
    if let Some(ref tid) = op.target_id {
        println!("Target ID:   {tid}");
    }
    if let Some(ref err) = op.error_message {
        println!("Error:       {err}");
    }
    println!(
        "Created:     {}",
        op.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(ref completed) = op.completed_at {
        println!("Completed:   {}", completed.format("%Y-%m-%d %H:%M:%S UTC"));
    }
}

fn print_queue_stats(stats: &QueueStatsResponse) {
    println!("Operation Queue Statistics");
    println!("{}", "\u{2501}".repeat(30));
    println!("Pending:     {}", stats.pending);
    println!("In Progress: {}", stats.in_progress);
    println!("Completed:   {}", stats.completed);
    println!("Failed:      {}", stats.failed);
    println!("Dead Letter: {}", stats.dead_letter);
}

fn print_job_table(jobs: &[JobResponse]) {
    println!(
        "{:<38} {:<15} {:<12} {:<24}",
        "ID", "TYPE", "STATUS", "CREATED"
    );
    println!("{}", "-".repeat(91));
    for job in jobs {
        println!(
            "{:<38} {:<15} {:<12} {:<24}",
            job.id,
            job.job_type.as_deref().unwrap_or("-"),
            job.status,
            job.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}

fn print_job_details(job: &JobResponse) {
    println!("Job: {}", job.id);
    println!("{}", "\u{2501}".repeat(50));
    println!("ID:          {}", job.id);
    if let Some(ref jtype) = job.job_type {
        println!("Type:        {jtype}");
    }
    println!("Status:      {}", job.status);
    if let Some(ref cid) = job.connector_id {
        println!("Connector:   {cid}");
    }
    println!(
        "Created:     {}",
        job.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(ref completed) = job.completed_at {
        println!("Completed:   {}", completed.format("%Y-%m-%d %H:%M:%S UTC"));
    }
}

fn print_dlq_table(entries: &[DlqEntryResponse]) {
    println!(
        "{:<38} {:<8} {:<38} {:<24}",
        "ID", "RETRIES", "ORIGINAL OP", "CREATED"
    );
    println!("{}", "-".repeat(110));
    for e in entries {
        println!(
            "{:<38} {:<8} {:<38} {:<24}",
            e.id,
            e.retry_count,
            e.original_operation_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            e.created_at.format("%Y-%m-%d %H:%M")
        );
    }
}
