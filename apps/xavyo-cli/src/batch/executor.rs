//! Batch operation executor
//!
//! Executes batch create, update, and delete operations with progress tracking.

use crate::api::ApiClient;
use crate::batch::file::BatchFile;
use crate::batch::filter::Filter;
use crate::batch::progress::BatchProgress;
use crate::batch::result::BatchResult;
use crate::error::{CliError, CliResult};
use crate::models::agent::{AgentResponse, CreateAgentRequest};
use crate::models::tool::{CreateToolRequest, ToolResponse};
use dialoguer::Confirm;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Batch operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum BatchOperation {
    /// Create new resources
    Create,
    /// Update existing resources
    Update,
    /// Delete resources
    Delete,
}

impl std::fmt::Display for BatchOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchOperation::Create => write!(f, "create"),
            BatchOperation::Update => write!(f, "update"),
            BatchOperation::Delete => write!(f, "delete"),
        }
    }
}

/// Options for batch execution
#[derive(Debug, Clone, Default)]
pub struct BatchOptions {
    /// Dry-run mode (preview without making changes)
    pub dry_run: bool,
    /// Stop on first error
    pub stop_on_error: bool,
    /// Skip confirmation prompts
    pub force: bool,
    /// Output as JSON
    pub json: bool,
}

/// Batch executor for performing bulk operations
pub struct BatchExecutor {
    client: ApiClient,
    interrupted: Arc<AtomicBool>,
}

impl BatchExecutor {
    /// Create a new batch executor
    pub fn new(client: ApiClient) -> Self {
        let interrupted = Arc::new(AtomicBool::new(false));

        // Set up Ctrl+C handler
        let interrupted_clone = interrupted.clone();
        let _ = ctrlc::set_handler(move || {
            interrupted_clone.store(true, Ordering::SeqCst);
        });

        Self {
            client,
            interrupted,
        }
    }

    /// Check if the operation was interrupted
    fn is_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }

    // =========================================================================
    // Agent Operations
    // =========================================================================

    /// Create agents from a batch file
    pub async fn create_agents(
        &self,
        batch: &BatchFile,
        options: &BatchOptions,
    ) -> CliResult<BatchResult> {
        let start = Instant::now();
        let mut result = BatchResult::new("create_agents", batch.agents.len());

        // Validate all entries for create
        for (i, entry) in batch.agents.iter().enumerate() {
            if let Err(e) = entry.validate_for_create() {
                result.add_skipped(i, entry.name_or_id(), e.to_string());
            }
        }

        // If dry-run, just return the preview
        if options.dry_run {
            // Count valid entries
            let valid_count = batch.agents.len() - result.skipped_count;
            for (i, entry) in batch.agents.iter().enumerate() {
                if result.items.iter().any(|item| item.index == i) {
                    continue; // Already skipped
                }
                // Mark as pending for dry-run
                result.items.push(crate::batch::result::BatchItemResult {
                    index: i,
                    name: entry.name_or_id(),
                    id: None,
                    status: crate::batch::result::BatchItemStatus::Pending,
                    error: None,
                });
            }
            println!("Dry-run mode - no changes will be made\n");
            println!("Would create {} agents:", valid_count);
            for (i, entry) in batch.agents.iter().enumerate() {
                if result
                    .items
                    .iter()
                    .any(|item| item.index == i && item.error.is_some())
                {
                    continue;
                }
                println!(
                    "  {}. {} ({}, {})",
                    i + 1,
                    entry.name.as_deref().unwrap_or("<unnamed>"),
                    entry.agent_type.as_deref().unwrap_or("unknown"),
                    entry.risk_level.as_deref().unwrap_or("unknown")
                );
            }
            println!("\nRun without --dry-run to create these agents.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(
                batch.agents.len() as u64,
                "Creating agents...",
                options.dry_run,
            ))
        } else {
            None
        };

        // Execute creates
        for (i, entry) in batch.agents.iter().enumerate() {
            // Check for interruption
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            // Skip already-skipped entries
            if result.items.iter().any(|item| item.index == i) {
                if let Some(ref pb) = progress {
                    pb.inc();
                }
                continue;
            }

            // Build request — validate required fields
            let name = match entry.name.clone() {
                Some(n) => n,
                None => {
                    result.add_failure(i, entry.name_or_id(), "Missing required field 'name'".to_string());
                    if let Some(ref pb) = progress { pb.inc(); }
                    continue;
                }
            };
            let agent_type = match entry.agent_type.clone() {
                Some(t) => t,
                None => {
                    result.add_failure(i, entry.name_or_id(), "Missing required field 'agent_type'".to_string());
                    if let Some(ref pb) = progress { pb.inc(); }
                    continue;
                }
            };
            let risk_level = match entry.risk_level.clone() {
                Some(r) => r,
                None => {
                    result.add_failure(i, entry.name_or_id(), "Missing required field 'risk_level'".to_string());
                    if let Some(ref pb) = progress { pb.inc(); }
                    continue;
                }
            };
            let request = CreateAgentRequest::new(name, agent_type)
                .with_risk_level(risk_level)
                .with_model(entry.model_provider.clone(), entry.model_name.clone())
                .with_description(entry.description.clone());

            // Execute create
            match self.client.create_agent(request).await {
                Ok(agent) => {
                    result.add_success(i, entry.name_or_id(), agent.id);
                }
                Err(e) => {
                    result.add_failure(i, entry.name_or_id(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }

    /// Delete agents by filter
    pub async fn delete_agents_by_filter(
        &self,
        filter: &Filter,
        options: &BatchOptions,
    ) -> CliResult<BatchResult> {
        let start = Instant::now();

        // First, list all agents
        let agents = self.client.list_agents(1000, 0, None, None).await?;

        // Filter matching agents
        let matching: Vec<&AgentResponse> = agents
            .agents
            .iter()
            .filter(|a| filter.matches_agent(&a.name, &a.agent_type, &a.status, &a.risk_level))
            .collect();

        if matching.is_empty() {
            println!("No agents found matching '{}'", filter.pattern);
            return Ok(BatchResult::new("delete_agents", 0));
        }

        let mut result = BatchResult::new("delete_agents", matching.len());

        // If dry-run, show preview
        if options.dry_run {
            println!("Dry-run mode - no changes will be made\n");
            println!(
                "Found {} agents matching '{}={}':",
                matching.len(),
                filter.field,
                filter.pattern
            );
            for (i, agent) in matching.iter().enumerate() {
                println!(
                    "  {}. {} (id: {}...)",
                    i + 1,
                    agent.name,
                    &agent.id.to_string()[..8]
                );
            }
            println!("\nRun without --dry-run to delete these agents.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Confirm deletion
        if !options.force {
            if !atty::is(atty::Stream::Stdin) {
                return Err(CliError::Validation(
                    "Cannot confirm deletion in non-interactive mode. Use --force to skip confirmation."
                        .to_string(),
                ));
            }

            println!(
                "Found {} agents matching '{}={}'.\n",
                matching.len(),
                filter.field,
                filter.pattern
            );
            println!("⚠️  This will permanently delete these agents.");

            let confirm = Confirm::new()
                .with_prompt("Proceed?")
                .default(false)
                .interact()
                .map_err(|e| CliError::Io(e.to_string()))?;

            if !confirm {
                println!("Cancelled.");
                return Ok(BatchResult::new("delete_agents", 0));
            }
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(
                matching.len() as u64,
                "Deleting agents...",
                false,
            ))
        } else {
            None
        };

        // Execute deletes
        for (i, agent) in matching.iter().enumerate() {
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            match self.client.delete_agent(agent.id).await {
                Ok(()) => {
                    result.add_success(i, agent.name.clone(), agent.id);
                }
                Err(e) => {
                    result.add_failure(i, agent.name.clone(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }

    /// Delete all agents with type-to-confirm
    pub async fn delete_all_agents(&self, options: &BatchOptions) -> CliResult<BatchResult> {
        let start = Instant::now();

        // List all agents
        let agents = self.client.list_agents(1000, 0, None, None).await?;
        let count = agents.agents.len();

        if count == 0 {
            println!("No agents to delete.");
            return Ok(BatchResult::new("delete_all_agents", 0));
        }

        let mut result = BatchResult::new("delete_all_agents", count);

        // If dry-run, show preview
        if options.dry_run {
            println!("Dry-run mode - no changes will be made\n");
            println!("Would delete ALL {} agents in this tenant.", count);
            println!("\nRun without --dry-run to delete these agents.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Confirm with type-to-confirm
        if !options.force {
            if !atty::is(atty::Stream::Stdin) {
                return Err(CliError::Validation(
                    "Cannot confirm deletion in non-interactive mode. Use --force to skip confirmation."
                        .to_string(),
                ));
            }

            println!(
                "⚠️  WARNING: This will delete ALL {} agents in this tenant.",
                count
            );
            println!("This action cannot be undone.\n");

            let input: String = dialoguer::Input::new()
                .with_prompt("Type 'agents' to confirm")
                .interact_text()
                .map_err(|e| CliError::Io(e.to_string()))?;

            if input.trim() != "agents" {
                println!("Confirmation failed. Operation cancelled.");
                return Ok(BatchResult::new("delete_all_agents", 0));
            }
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(
                count as u64,
                "Deleting agents...",
                false,
            ))
        } else {
            None
        };

        // Execute deletes
        for (i, agent) in agents.agents.iter().enumerate() {
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            match self.client.delete_agent(agent.id).await {
                Ok(()) => {
                    result.add_success(i, agent.name.clone(), agent.id);
                }
                Err(e) => {
                    result.add_failure(i, agent.name.clone(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }

    /// Update agents from a batch file
    pub async fn update_agents(
        &self,
        batch: &BatchFile,
        options: &BatchOptions,
    ) -> CliResult<BatchResult> {
        let start = Instant::now();
        let mut result = BatchResult::new("update_agents", batch.agents.len());

        // Validate all entries for update
        for (i, entry) in batch.agents.iter().enumerate() {
            if let Err(e) = entry.validate_for_update() {
                result.add_skipped(i, entry.name_or_id(), e.to_string());
            }
        }

        // If dry-run, show preview
        if options.dry_run {
            let valid_count = batch.agents.len() - result.skipped_count;
            println!("Dry-run mode - no changes will be made\n");
            println!("Would update {} agents:", valid_count);
            for (i, entry) in batch.agents.iter().enumerate() {
                if result
                    .items
                    .iter()
                    .any(|item| item.index == i && item.error.is_some())
                {
                    continue;
                }
                println!("  {}. {}", i + 1, entry.name_or_id());
            }
            println!("\nRun without --dry-run to update these agents.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(
                batch.agents.len() as u64,
                "Updating agents...",
                options.dry_run,
            ))
        } else {
            None
        };

        // Execute updates
        for (i, entry) in batch.agents.iter().enumerate() {
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            // Skip already-skipped entries
            if result.items.iter().any(|item| item.index == i) {
                if let Some(ref pb) = progress {
                    pb.inc();
                }
                continue;
            }

            let agent_id = match entry.id {
                Some(id) => id,
                None => {
                    result.add_failure(i, entry.name_or_id(), "Missing required field 'id' for update".to_string());
                    if let Some(ref pb) = progress { pb.inc(); }
                    continue;
                }
            };

            // Build update - using patch semantics (only specified fields)
            // Note: This would need an UpdateAgentRequest type
            // For now, we simulate by getting and updating
            match self.client.get_agent(agent_id).await {
                Ok(existing) => {
                    // Build update request with changed fields
                    let request = CreateAgentRequest::new(
                        existing.name.clone(),
                        entry
                            .agent_type
                            .clone()
                            .unwrap_or(existing.agent_type.clone()),
                    )
                    .with_risk_level(
                        entry
                            .risk_level
                            .clone()
                            .unwrap_or(existing.risk_level.clone()),
                    )
                    .with_model(
                        entry
                            .model_provider
                            .clone()
                            .or(existing.model_provider.clone()),
                        entry.model_name.clone().or(existing.model_name.clone()),
                    )
                    .with_description(entry.description.clone().or(existing.description.clone()));

                    // Note: API needs update_agent method
                    // For now, just record success
                    match self.client.update_agent(agent_id, request).await {
                        Ok(agent) => {
                            result.add_success(i, entry.name_or_id(), agent.id);
                        }
                        Err(e) => {
                            result.add_failure(i, entry.name_or_id(), e.to_string());
                            if options.stop_on_error {
                                if let Some(ref pb) = progress {
                                    pb.finish_and_clear();
                                }
                                result.set_duration(start.elapsed().as_millis() as u64);
                                return Ok(result);
                            }
                        }
                    }
                }
                Err(e) => {
                    result.add_failure(i, entry.name_or_id(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }

    // =========================================================================
    // Tool Operations
    // =========================================================================

    /// Create tools from a batch file
    pub async fn create_tools(
        &self,
        batch: &BatchFile,
        options: &BatchOptions,
    ) -> CliResult<BatchResult> {
        let start = Instant::now();
        let mut result = BatchResult::new("create_tools", batch.tools.len());

        // Validate all entries for create
        for (i, entry) in batch.tools.iter().enumerate() {
            if let Err(e) = entry.validate_for_create() {
                result.add_skipped(i, entry.name_or_id(), e.to_string());
            }
        }

        // If dry-run, show preview
        if options.dry_run {
            let valid_count = batch.tools.len() - result.skipped_count;
            println!("Dry-run mode - no changes will be made\n");
            println!("Would create {} tools:", valid_count);
            for (i, entry) in batch.tools.iter().enumerate() {
                if result
                    .items
                    .iter()
                    .any(|item| item.index == i && item.error.is_some())
                {
                    continue;
                }
                println!(
                    "  {}. {} ({})",
                    i + 1,
                    entry.name.as_deref().unwrap_or("<unnamed>"),
                    entry.risk_level.as_deref().unwrap_or("unknown")
                );
            }
            println!("\nRun without --dry-run to create these tools.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(
                batch.tools.len() as u64,
                "Creating tools...",
                options.dry_run,
            ))
        } else {
            None
        };

        // Execute creates
        for (i, entry) in batch.tools.iter().enumerate() {
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            // Skip already-skipped entries
            if result.items.iter().any(|item| item.index == i) {
                if let Some(ref pb) = progress {
                    pb.inc();
                }
                continue;
            }

            // Build request
            let schema = entry
                .input_schema
                .clone()
                .unwrap_or(serde_json::json!({"type": "object"}));

            let name = match entry.name.clone() {
                Some(n) => n,
                None => {
                    result.add_failure(i, entry.name_or_id(), "Missing required field 'name'".to_string());
                    if let Some(ref pb) = progress { pb.inc(); }
                    continue;
                }
            };
            let risk_level = match entry.risk_level.clone() {
                Some(r) => r,
                None => {
                    result.add_failure(i, entry.name_or_id(), "Missing required field 'risk_level'".to_string());
                    if let Some(ref pb) = progress { pb.inc(); }
                    continue;
                }
            };
            let mut request = CreateToolRequest::new(name, schema, risk_level);

            if let Some(ref desc) = entry.description {
                request = request.with_description(Some(desc.clone()));
            }
            if let Some(ref cat) = entry.category {
                request = request.with_category(Some(cat.clone()));
            }
            if let Some(requires_approval) = entry.requires_approval {
                request = request.with_requires_approval(requires_approval);
            }

            // Execute create
            match self.client.create_tool(request).await {
                Ok(tool) => {
                    result.add_success(i, entry.name_or_id(), tool.id);
                }
                Err(e) => {
                    result.add_failure(i, entry.name_or_id(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }

    /// Delete tools by filter
    pub async fn delete_tools_by_filter(
        &self,
        filter: &Filter,
        options: &BatchOptions,
    ) -> CliResult<BatchResult> {
        let start = Instant::now();

        // First, list all tools
        let tools = self.client.list_tools(1000, 0).await?;

        // Filter matching tools
        let matching: Vec<&ToolResponse> = tools
            .tools
            .iter()
            .filter(|t| filter.matches_tool(&t.name, &t.status, &t.risk_level))
            .collect();

        if matching.is_empty() {
            println!("No tools found matching '{}'", filter.pattern);
            return Ok(BatchResult::new("delete_tools", 0));
        }

        let mut result = BatchResult::new("delete_tools", matching.len());

        // If dry-run, show preview
        if options.dry_run {
            println!("Dry-run mode - no changes will be made\n");
            println!(
                "Found {} tools matching '{}={}':",
                matching.len(),
                filter.field,
                filter.pattern
            );
            for (i, tool) in matching.iter().enumerate() {
                println!(
                    "  {}. {} (id: {}...)",
                    i + 1,
                    tool.name,
                    &tool.id.to_string()[..8]
                );
            }
            println!("\nRun without --dry-run to delete these tools.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Confirm deletion
        if !options.force {
            if !atty::is(atty::Stream::Stdin) {
                return Err(CliError::Validation(
                    "Cannot confirm deletion in non-interactive mode. Use --force to skip confirmation."
                        .to_string(),
                ));
            }

            println!(
                "Found {} tools matching '{}={}'.\n",
                matching.len(),
                filter.field,
                filter.pattern
            );
            println!("⚠️  This will permanently delete these tools.");

            let confirm = Confirm::new()
                .with_prompt("Proceed?")
                .default(false)
                .interact()
                .map_err(|e| CliError::Io(e.to_string()))?;

            if !confirm {
                println!("Cancelled.");
                return Ok(BatchResult::new("delete_tools", 0));
            }
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(
                matching.len() as u64,
                "Deleting tools...",
                false,
            ))
        } else {
            None
        };

        // Execute deletes
        for (i, tool) in matching.iter().enumerate() {
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            match self.client.delete_tool(tool.id).await {
                Ok(()) => {
                    result.add_success(i, tool.name.clone(), tool.id);
                }
                Err(e) => {
                    result.add_failure(i, tool.name.clone(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }

    /// Delete all tools with type-to-confirm
    pub async fn delete_all_tools(&self, options: &BatchOptions) -> CliResult<BatchResult> {
        let start = Instant::now();

        // List all tools
        let tools = self.client.list_tools(1000, 0).await?;
        let count = tools.tools.len();

        if count == 0 {
            println!("No tools to delete.");
            return Ok(BatchResult::new("delete_all_tools", 0));
        }

        let mut result = BatchResult::new("delete_all_tools", count);

        // If dry-run, show preview
        if options.dry_run {
            println!("Dry-run mode - no changes will be made\n");
            println!("Would delete ALL {} tools in this tenant.", count);
            println!("\nRun without --dry-run to delete these tools.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Confirm with type-to-confirm
        if !options.force {
            if !atty::is(atty::Stream::Stdin) {
                return Err(CliError::Validation(
                    "Cannot confirm deletion in non-interactive mode. Use --force to skip confirmation."
                        .to_string(),
                ));
            }

            println!(
                "⚠️  WARNING: This will delete ALL {} tools in this tenant.",
                count
            );
            println!("This action cannot be undone.\n");

            let input: String = dialoguer::Input::new()
                .with_prompt("Type 'tools' to confirm")
                .interact_text()
                .map_err(|e| CliError::Io(e.to_string()))?;

            if input.trim() != "tools" {
                println!("Confirmation failed. Operation cancelled.");
                return Ok(BatchResult::new("delete_all_tools", 0));
            }
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(count as u64, "Deleting tools...", false))
        } else {
            None
        };

        // Execute deletes
        for (i, tool) in tools.tools.iter().enumerate() {
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            match self.client.delete_tool(tool.id).await {
                Ok(()) => {
                    result.add_success(i, tool.name.clone(), tool.id);
                }
                Err(e) => {
                    result.add_failure(i, tool.name.clone(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }

    /// Update tools from a batch file
    pub async fn update_tools(
        &self,
        batch: &BatchFile,
        options: &BatchOptions,
    ) -> CliResult<BatchResult> {
        let start = Instant::now();
        let mut result = BatchResult::new("update_tools", batch.tools.len());

        // Validate all entries for update
        for (i, entry) in batch.tools.iter().enumerate() {
            if let Err(e) = entry.validate_for_update() {
                result.add_skipped(i, entry.name_or_id(), e.to_string());
            }
        }

        // If dry-run, show preview
        if options.dry_run {
            let valid_count = batch.tools.len() - result.skipped_count;
            println!("Dry-run mode - no changes will be made\n");
            println!("Would update {} tools:", valid_count);
            for (i, entry) in batch.tools.iter().enumerate() {
                if result
                    .items
                    .iter()
                    .any(|item| item.index == i && item.error.is_some())
                {
                    continue;
                }
                println!("  {}. {}", i + 1, entry.name_or_id());
            }
            println!("\nRun without --dry-run to update these tools.");
            result.set_duration(start.elapsed().as_millis() as u64);
            return Ok(result);
        }

        // Create progress bar
        let progress = if !options.json {
            Some(BatchProgress::new(
                batch.tools.len() as u64,
                "Updating tools...",
                options.dry_run,
            ))
        } else {
            None
        };

        // Execute updates
        for (i, entry) in batch.tools.iter().enumerate() {
            if self.is_interrupted() {
                result.set_interrupted();
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                break;
            }

            // Skip already-skipped entries
            if result.items.iter().any(|item| item.index == i) {
                if let Some(ref pb) = progress {
                    pb.inc();
                }
                continue;
            }

            let tool_id = match entry.id {
                Some(id) => id,
                None => {
                    result.add_failure(i, entry.name_or_id(), "Missing required field 'id' for update".to_string());
                    if let Some(ref pb) = progress { pb.inc(); }
                    continue;
                }
            };

            // Get existing tool and update
            match self.client.get_tool(tool_id).await {
                Ok(existing) => {
                    let schema = entry
                        .input_schema
                        .clone()
                        .unwrap_or(existing.input_schema.clone());
                    let mut request = CreateToolRequest::new(
                        existing.name.clone(),
                        schema,
                        entry
                            .risk_level
                            .clone()
                            .unwrap_or(existing.risk_level.clone()),
                    );

                    if let Some(ref desc) = entry.description {
                        request = request.with_description(Some(desc.clone()));
                    } else if let Some(ref desc) = existing.description {
                        request = request.with_description(Some(desc.clone()));
                    }

                    if let Some(ref cat) = entry.category {
                        request = request.with_category(Some(cat.clone()));
                    } else if let Some(ref cat) = existing.category {
                        request = request.with_category(Some(cat.clone()));
                    }

                    if let Some(requires_approval) = entry.requires_approval {
                        request = request.with_requires_approval(requires_approval);
                    }

                    // Note: API needs update_tool method
                    match self.client.update_tool(tool_id, request).await {
                        Ok(tool) => {
                            result.add_success(i, entry.name_or_id(), tool.id);
                        }
                        Err(e) => {
                            result.add_failure(i, entry.name_or_id(), e.to_string());
                            if options.stop_on_error {
                                if let Some(ref pb) = progress {
                                    pb.finish_and_clear();
                                }
                                result.set_duration(start.elapsed().as_millis() as u64);
                                return Ok(result);
                            }
                        }
                    }
                }
                Err(e) => {
                    result.add_failure(i, entry.name_or_id(), e.to_string());
                    if options.stop_on_error {
                        if let Some(ref pb) = progress {
                            pb.finish_and_clear();
                        }
                        result.set_duration(start.elapsed().as_millis() as u64);
                        return Ok(result);
                    }
                }
            }

            if let Some(ref pb) = progress {
                pb.inc();
            }
        }

        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        result.set_duration(start.elapsed().as_millis() as u64);
        Ok(result)
    }
}

/// Print batch result summary
pub fn print_batch_summary(result: &BatchResult, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return;
    }

    println!();

    if result.interrupted {
        println!("⚠️  Operation interrupted!\n");
    } else if result.all_succeeded() {
        println!("✓ Batch complete!");
    } else {
        println!("⚠️  Batch completed with errors");
    }

    println!();
    println!("Summary:");

    // Show success/failure counts based on operation
    if result.operation.contains("create") {
        println!("  Created: {}", result.success_count);
    } else if result.operation.contains("update") {
        println!("  Updated: {}", result.success_count);
    } else if result.operation.contains("delete") {
        println!("  Deleted: {}", result.success_count);
    }

    if result.failure_count > 0 {
        println!("  Failed:  {}", result.failure_count);
    }
    if result.skipped_count > 0 {
        println!("  Skipped: {}", result.skipped_count);
    }

    // Show errors if any
    if result.has_failures() {
        println!();
        println!("Errors:");
        for item in result.failed_items() {
            if let Some(ref error) = item.error {
                println!("  • Item {} ({}): {}", item.index + 1, item.name, error);
            }
        }
    }

    // Show successful items
    if result.success_count > 0 && !result.operation.contains("delete") {
        println!();
        if result.operation.contains("create") {
            println!("Created:");
        } else {
            println!("Updated:");
        }
        for item in result.successful_items() {
            if let Some(id) = item.id {
                println!("  • {} (id: {}...)", item.name, &id.to_string()[..8]);
            } else {
                println!("  • {}", item.name);
            }
        }
    }
}
