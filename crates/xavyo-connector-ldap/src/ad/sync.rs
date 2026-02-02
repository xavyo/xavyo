//! AD user synchronization with uSNChanged-based incremental sync.
//!
//! Implements the `SyncCapable` trait for `AdConnector`, providing:
//! - Full sync: enumerate all AD users with paged search
//! - Incremental sync: poll for changes using uSNChanged
//! - Attribute mapping from AD schema to platform user model
//! - userAccountControl-based active/disabled detection

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, instrument, warn};

use xavyo_connector::operation::{AttributeSet, AttributeValue};
use xavyo_connector::traits::{SyncChange, SyncChangeType, SyncResult};

use super::user_account_control::UserAccountControl;

/// Checkpoint stored as the uSNChanged sync token.
///
/// Contains the highest committed USN from the last sync plus the DC hostname,
/// so we can detect DC failovers that would invalidate the checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnCheckpoint {
    /// Highest uSNChanged value processed in last sync.
    pub usn: String,
    /// Hostname of the domain controller that provided this USN.
    pub dc: String,
}

impl UsnCheckpoint {
    /// Create a new checkpoint.
    pub fn new(usn: impl Into<String>, dc: impl Into<String>) -> Self {
        Self {
            usn: usn.into(),
            dc: dc.into(),
        }
    }

    /// Serialize to JSON string for storage as sync token.
    pub fn to_token(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse from a sync token string.
    pub fn from_token(token: &str) -> Option<Self> {
        serde_json::from_str(token).ok()
    }

    /// Build an LDAP filter for fetching changes since this checkpoint.
    ///
    /// Combines with the base user or group filter using AND.
    ///
    /// SECURITY: The USN value is escaped to prevent LDAP injection attacks.
    pub fn incremental_filter(&self, base_filter: &str, attribute: &str) -> String {
        // SECURITY: Escape the USN value to prevent LDAP injection.
        // While USN values from AD should be numeric, we escape them anyway
        // to protect against any potential manipulation of stored sync tokens.
        let escaped_usn = Self::escape_ldap_value(&self.usn);
        format!(
            "(&{}({}>={})(!({}={})))",
            base_filter, attribute, escaped_usn, attribute, escaped_usn
        )
    }

    /// Escape special characters in LDAP filter values (RFC 4515).
    ///
    /// Characters that must be escaped: * ( ) \ NUL
    fn escape_ldap_value(value: &str) -> String {
        value
            .replace('\\', "\\5c")
            .replace('*', "\\2a")
            .replace('(', "\\28")
            .replace(')', "\\29")
            .replace('\0', "\\00")
    }
}

/// Result of mapping a single AD entry to platform attributes.
#[derive(Debug, Clone)]
pub struct MappedUser {
    /// External unique identifier (objectGUID as base64).
    pub external_id: String,
    /// Distinguished name.
    pub dn: String,
    /// Mapped platform attributes.
    pub attributes: HashMap<String, serde_json::Value>,
    /// Whether the account is active (not disabled).
    pub is_active: bool,
    /// Raw UAC value for audit.
    pub uac_value: Option<u32>,
    /// uSNChanged value for checkpoint tracking.
    pub usn_changed: Option<String>,
}

/// Map an AD user LDAP entry (as AttributeSet) to a platform-compatible MappedUser.
///
/// Attribute mapping follows the data-model.md reference:
/// - objectGUID -> external_id (binary to base64)
/// - sAMAccountName -> username
/// - userPrincipalName -> upn
/// - mail -> email
/// - displayName -> display_name
/// - givenName -> first_name
/// - sn -> last_name
/// - department -> department
/// - title -> job_title
/// - employeeID -> employee_id
/// - manager -> manager_dn (raw DN, resolved in post-processing)
/// - userAccountControl -> is_active (bit 0x2 = disabled)
/// - whenCreated -> ad_when_created
/// - whenChanged -> ad_when_changed
pub fn map_ad_user(entry: &AttributeSet) -> Option<MappedUser> {
    // Extract objectGUID (required for unique identification)
    let external_id = extract_object_guid(entry)?;
    debug!(external_id = %external_id, "Mapping AD user entry");

    // Extract DN
    let dn = entry
        .get_string("distinguishedName")
        .or_else(|| entry.get_string("dn"))
        .unwrap_or("")
        .to_string();

    let mut attrs = HashMap::new();

    // Identity attributes
    set_if_present(&mut attrs, "username", entry.get_string("sAMAccountName"));
    set_if_present(&mut attrs, "upn", entry.get_string("userPrincipalName"));
    set_if_present(&mut attrs, "email", entry.get_string("mail"));

    // Name attributes
    set_if_present(&mut attrs, "display_name", entry.get_string("displayName"));
    set_if_present(&mut attrs, "first_name", entry.get_string("givenName"));
    set_if_present(&mut attrs, "last_name", entry.get_string("sn"));

    // Build cn as fallback display name
    if !attrs.contains_key("display_name") {
        set_if_present(&mut attrs, "display_name", entry.get_string("cn"));
    }

    // Organizational attributes
    set_if_present(&mut attrs, "department", entry.get_string("department"));
    set_if_present(&mut attrs, "job_title", entry.get_string("title"));
    set_if_present(&mut attrs, "company", entry.get_string("company"));
    set_if_present(&mut attrs, "employee_id", entry.get_string("employeeID"));
    set_if_present(
        &mut attrs,
        "employee_number",
        entry.get_string("employeeNumber"),
    );
    set_if_present(&mut attrs, "phone", entry.get_string("telephoneNumber"));

    // Manager DN (resolved in post-processing)
    set_if_present(&mut attrs, "manager_dn", entry.get_string("manager"));

    // Distinguished name in attrs for reference
    if !dn.is_empty() {
        attrs.insert("dn".to_string(), serde_json::Value::String(dn.clone()));
    }

    // Group memberships (multi-valued)
    if let Some(member_of) = entry.get("memberOf") {
        match member_of {
            AttributeValue::Array(arr) => {
                let dns: Vec<serde_json::Value> = arr
                    .iter()
                    .filter_map(|v| {
                        v.as_string()
                            .map(|s| serde_json::Value::String(s.to_string()))
                    })
                    .collect();
                if !dns.is_empty() {
                    attrs.insert("member_of_dns".to_string(), serde_json::Value::Array(dns));
                }
            }
            AttributeValue::String(s) => {
                attrs.insert("member_of_dns".to_string(), serde_json::json!([s]));
            }
            _ => {}
        }
    }

    // Parse userAccountControl
    let (is_active, uac_value) = parse_uac(entry);

    // Timestamps
    set_if_present(
        &mut attrs,
        "ad_when_created",
        entry.get_string("whenCreated"),
    );
    set_if_present(
        &mut attrs,
        "ad_when_changed",
        entry.get_string("whenChanged"),
    );

    // uSNChanged for checkpoint tracking
    let usn_changed = entry.get_string("uSNChanged").map(|s| s.to_string());

    Some(MappedUser {
        external_id,
        dn,
        attributes: attrs,
        is_active,
        uac_value,
        usn_changed,
    })
}

/// Build a SyncChange from a MappedUser.
pub fn mapped_user_to_sync_change(user: &MappedUser, change_type: SyncChangeType) -> SyncChange {
    let mut attrs = AttributeSet::new();

    // Copy all mapped attributes into the AttributeSet
    for (key, value) in &user.attributes {
        match value {
            serde_json::Value::String(s) => {
                attrs.set(key.clone(), s.clone());
            }
            serde_json::Value::Array(arr) => {
                let values: Vec<AttributeValue> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| AttributeValue::String(s.to_string())))
                    .collect();
                attrs.set(key.clone(), AttributeValue::Array(values));
            }
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    attrs.set(key.clone(), i);
                }
            }
            serde_json::Value::Bool(b) => {
                attrs.set(key.clone(), *b);
            }
            _ => {}
        }
    }

    // Set is_active as a boolean attribute
    attrs.set("is_active", user.is_active);

    // Set external_id
    attrs.set("external_id", user.external_id.clone());

    let uid = xavyo_connector::operation::Uid::new("objectGUID", &user.external_id);

    match change_type {
        SyncChangeType::Create => SyncChange::created(uid, "user", attrs),
        SyncChangeType::Update => SyncChange::updated(uid, "user", attrs),
        SyncChangeType::Delete => SyncChange::deleted(uid, "user"),
    }
}

/// Build a SyncResult from a batch of mapped users.
#[instrument(skip(users), fields(user_count = users.len(), has_more))]
pub fn build_sync_result(
    users: Vec<MappedUser>,
    change_type: SyncChangeType,
    new_checkpoint: Option<UsnCheckpoint>,
    has_more: bool,
) -> SyncResult {
    info!(
        user_count = users.len(),
        ?change_type,
        "Building sync result"
    );
    let changes: Vec<SyncChange> = users
        .iter()
        .map(|u| mapped_user_to_sync_change(u, change_type))
        .collect();

    let mut result = SyncResult::with_changes(changes);

    if let Some(checkpoint) = new_checkpoint {
        result = result.with_token(checkpoint.to_token());
    }

    if has_more {
        result = result.with_more();
    }

    result
}

/// Compute the highest uSNChanged value from a batch of mapped users.
pub fn highest_usn(users: &[MappedUser]) -> Option<String> {
    users
        .iter()
        .filter_map(|u| u.usn_changed.as_ref())
        .filter_map(|s| s.parse::<u64>().ok())
        .max()
        .map(|v| v.to_string())
}

/// Extract objectGUID from an LDAP entry as base64-encoded string.
///
/// objectGUID is a 16-byte binary attribute in AD. We encode it as standard
/// base64 for storage as the external_id / unique identifier.
fn extract_object_guid(entry: &AttributeSet) -> Option<String> {
    match entry.get("objectGUID") {
        Some(AttributeValue::Binary(bytes)) => {
            Some(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        Some(AttributeValue::String(s)) => {
            // Already a string (e.g., from deserialization) — use as-is
            if !s.is_empty() {
                Some(s.clone())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Parse userAccountControl from an entry and return (is_active, raw_value).
fn parse_uac(entry: &AttributeSet) -> (bool, Option<u32>) {
    match entry.get("userAccountControl") {
        Some(AttributeValue::Integer(i)) => {
            let uac = UserAccountControl::from_value(*i as u32);
            (uac.is_active(), Some(uac.value))
        }
        Some(AttributeValue::String(s)) => {
            if let Ok(val) = s.parse::<u32>() {
                let uac = UserAccountControl::from_value(val);
                (uac.is_active(), Some(uac.value))
            } else {
                (true, None) // Default to active if unparseable
            }
        }
        _ => (true, None), // Default to active if not present
    }
}

/// Set a value in the attributes map if the option is Some and non-empty.
fn set_if_present(attrs: &mut HashMap<String, serde_json::Value>, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        if !v.is_empty() {
            attrs.insert(key.to_string(), serde_json::Value::String(v.to_string()));
        }
    }
}

/// Build the LDAP attribute list for AD user sync queries.
///
/// Returns the list of LDAP attributes to request when searching for users.
pub fn user_sync_attributes() -> Vec<&'static str> {
    vec![
        "objectGUID",
        "distinguishedName",
        "sAMAccountName",
        "userPrincipalName",
        "cn",
        "displayName",
        "givenName",
        "sn",
        "mail",
        "telephoneNumber",
        "department",
        "title",
        "company",
        "employeeID",
        "employeeNumber",
        "manager",
        "userAccountControl",
        "memberOf",
        "whenCreated",
        "whenChanged",
        "uSNChanged",
    ]
}

/// Result of manager resolution post-processing.
#[derive(Debug, Clone)]
pub struct ManagerResolutionResult {
    /// Number of users that had a manager_dn.
    pub total_with_manager: usize,
    /// Number of manager_dn values successfully resolved to external_id.
    pub resolved: usize,
    /// Number of manager_dn values that could not be resolved (manager not in sync set).
    pub unresolved: usize,
    /// DNs of unresolved managers (for logging/diagnostics).
    pub unresolved_dns: Vec<String>,
}

/// Resolve manager relationships in a batch of mapped users.
///
/// After importing all users, each user's `manager_dn` attribute contains the
/// Distinguished Name of their manager. This function resolves those DNs to the
/// manager's `external_id` (objectGUID) using a DN→external_id lookup built
/// from the same batch.
///
/// For managers not found in the batch (e.g., in a different OU or not yet
/// imported), the manager_dn is left in place and logged as unresolved.
///
/// # Arguments
/// * `users` — mutable slice of mapped users to resolve
/// * `dn_to_external_id` — lookup map from DN (case-insensitive key) to external_id
#[instrument(skip(users, dn_to_external_id), fields(user_count = users.len(), lookup_size = dn_to_external_id.len()))]
pub fn resolve_manager_references(
    users: &mut [MappedUser],
    dn_to_external_id: &HashMap<String, String>,
) -> ManagerResolutionResult {
    let mut total_with_manager = 0;
    let mut resolved = 0;
    let mut unresolved = 0;
    let mut unresolved_dns = Vec::new();

    for user in users.iter_mut() {
        let manager_dn = match user.attributes.get("manager_dn") {
            Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
            _ => continue,
        };
        total_with_manager += 1;

        // Look up by lowercase DN for case-insensitive matching (AD DNs are case-insensitive)
        let lookup_key = manager_dn.to_lowercase();
        if let Some(manager_ext_id) = dn_to_external_id.get(&lookup_key) {
            user.attributes.insert(
                "manager_external_id".to_string(),
                serde_json::Value::String(manager_ext_id.clone()),
            );
            resolved += 1;
        } else {
            unresolved += 1;
            unresolved_dns.push(manager_dn);
        }
    }

    ManagerResolutionResult {
        total_with_manager,
        resolved,
        unresolved,
        unresolved_dns,
    }
}

/// Build a DN→external_id lookup map from a batch of mapped users.
///
/// Keys are lowercased for case-insensitive matching.
pub fn build_dn_lookup(users: &[MappedUser]) -> HashMap<String, String> {
    users
        .iter()
        .filter(|u| !u.dn.is_empty())
        .map(|u| (u.dn.to_lowercase(), u.external_id.clone()))
        .collect()
}

// --- T036/T037: Partial sync with per-record error handling and statistics ---

/// Statistics for an AD sync run.
///
/// Tracks per-record success/failure counts and sync metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdSyncStatistics {
    /// Total records encountered.
    pub total: usize,
    /// Records successfully processed.
    pub processed: usize,
    /// Records created (new to platform).
    pub created: usize,
    /// Records updated (changed since last sync).
    pub updated: usize,
    /// Records deleted (removed from AD).
    pub deleted: usize,
    /// Records skipped (e.g., missing required fields).
    pub skipped: usize,
    /// Records that failed to process.
    pub errors: usize,
    /// Per-record error details (DN → error message).
    pub error_details: Vec<SyncRecordError>,
    /// Sync type (full or delta).
    pub sync_type: String,
    /// USN checkpoint after this run (if any).
    pub usn_checkpoint: Option<String>,
    /// Search bases processed.
    pub search_bases_processed: usize,
    /// Domain controller used.
    pub domain_controller: Option<String>,
}

/// Error details for a single record that failed during sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRecordError {
    /// Distinguished name of the failed record.
    pub dn: String,
    /// Error message.
    pub error: String,
    /// Phase where the error occurred (mapping, import, membership).
    pub phase: String,
}

impl AdSyncStatistics {
    /// Create a new statistics tracker for a sync run.
    pub fn new(sync_type: &str) -> Self {
        Self {
            sync_type: sync_type.to_string(),
            ..Default::default()
        }
    }

    /// Record a successfully mapped and imported record.
    pub fn record_success(&mut self, is_new: bool) {
        self.processed += 1;
        if is_new {
            self.created += 1;
        } else {
            self.updated += 1;
        }
    }

    /// Record a skipped record (e.g., no objectGUID).
    pub fn record_skip(&mut self) {
        self.skipped += 1;
    }

    /// Record a failed record with error details.
    pub fn record_error(&mut self, dn: &str, error: &str, phase: &str) {
        self.errors += 1;
        warn!(dn = %dn, phase = %phase, error = %error, "AD sync record failed");
        self.error_details.push(SyncRecordError {
            dn: dn.to_string(),
            error: error.to_string(),
            phase: phase.to_string(),
        });
    }

    /// Whether the run completed at least partially (some records succeeded).
    pub fn has_successes(&self) -> bool {
        self.processed > 0
    }

    /// Convert to a serde_json::Value for storage in reconciliation_runs.statistics.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::json!({}))
    }
}

/// Process a batch of AD user entries with per-record error resilience.
///
/// Each record is processed independently: if one record fails to map or
/// import, the error is recorded and processing continues with the next record.
/// This ensures a single bad record doesn't abort the entire sync run.
///
/// # Arguments
/// * `entries` — AD user entries from LDAP search
/// * `stats` — mutable statistics accumulator
///
/// # Returns
/// Successfully mapped users (failures are recorded in stats.error_details).
#[instrument(skip(entries, stats), fields(batch_size = entries.len()))]
pub fn process_user_batch_resilient(
    entries: &[AttributeSet],
    stats: &mut AdSyncStatistics,
) -> Vec<MappedUser> {
    info!(batch_size = entries.len(), "Processing AD user batch");
    let mut users = Vec::with_capacity(entries.len());
    stats.total += entries.len();

    for entry in entries {
        let dn = entry
            .get_string("distinguishedName")
            .or_else(|| entry.get_string("dn"))
            .unwrap_or("<unknown>")
            .to_string();

        match map_ad_user(entry) {
            Some(user) => {
                users.push(user);
            }
            None => {
                // No objectGUID → skip (not an error, just unmappable)
                stats.record_skip();
                debug!(dn = %dn, "Skipping AD entry: no objectGUID");
            }
        }
    }

    users
}

/// Retry configuration specific to AD sync operations.
///
/// Uses the existing RetryConfig from xavyo-connector but provides
/// AD-specific defaults for sync operations.
#[derive(Debug, Clone)]
pub struct AdRetryConfig {
    /// Maximum number of retries for connection failures.
    pub max_retries: u32,
    /// Initial retry delay.
    pub initial_delay_secs: u64,
    /// Maximum retry delay cap.
    pub max_delay_secs: u64,
    /// Backoff multiplier (exponential factor).
    pub backoff_multiplier: f64,
}

impl Default for AdRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_secs: 1,
            max_delay_secs: 30,
            backoff_multiplier: 2.0,
        }
    }
}

impl AdRetryConfig {
    /// Calculate the delay for a given attempt number.
    ///
    /// Uses exponential backoff: delay = initial * multiplier^attempt
    /// Capped at max_delay.
    pub fn delay_for_attempt(&self, attempt: u32) -> std::time::Duration {
        let delay_secs =
            (self.initial_delay_secs as f64) * self.backoff_multiplier.powi(attempt as i32);
        let capped = delay_secs.min(self.max_delay_secs as f64);
        std::time::Duration::from_secs_f64(capped)
    }

    /// Check if a retry should be attempted.
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_connector::operation::{AttributeSet, AttributeValue};

    // --- T009: Tests for AD user attribute mapping ---

    fn sample_ad_user_entry() -> AttributeSet {
        let mut attrs = AttributeSet::new();
        // objectGUID as binary (16 bytes)
        attrs.set(
            "objectGUID",
            AttributeValue::Binary(vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ]),
        );
        attrs.set(
            "distinguishedName",
            "CN=John Doe,OU=Users,DC=example,DC=com",
        );
        attrs.set("sAMAccountName", "john.doe");
        attrs.set("userPrincipalName", "john.doe@example.com");
        attrs.set("cn", "John Doe");
        attrs.set("displayName", "John Doe");
        attrs.set("givenName", "John");
        attrs.set("sn", "Doe");
        attrs.set("mail", "john.doe@example.com");
        attrs.set("telephoneNumber", "+1-555-0100");
        attrs.set("department", "Engineering");
        attrs.set("title", "Senior Developer");
        attrs.set("company", "Example Corp");
        attrs.set("employeeID", "EMP001");
        attrs.set("employeeNumber", "12345");
        attrs.set("manager", "CN=Jane Boss,OU=Users,DC=example,DC=com");
        // Normal account (0x200) — active
        attrs.set("userAccountControl", AttributeValue::Integer(0x200));
        attrs.set(
            "memberOf",
            AttributeValue::Array(vec![
                AttributeValue::String("CN=Developers,OU=Groups,DC=example,DC=com".to_string()),
                AttributeValue::String("CN=AllStaff,OU=Groups,DC=example,DC=com".to_string()),
            ]),
        );
        attrs.set("whenCreated", "20240115120000.0Z");
        attrs.set("whenChanged", "20240620153045.0Z");
        attrs.set("uSNChanged", "123456");
        attrs
    }

    #[test]
    fn test_map_ad_user_basic_attributes() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        assert_eq!(mapped.attributes["username"], "john.doe");
        assert_eq!(mapped.attributes["upn"], "john.doe@example.com");
        assert_eq!(mapped.attributes["email"], "john.doe@example.com");
        assert_eq!(mapped.attributes["display_name"], "John Doe");
        assert_eq!(mapped.attributes["first_name"], "John");
        assert_eq!(mapped.attributes["last_name"], "Doe");
        assert_eq!(mapped.attributes["phone"], "+1-555-0100");
    }

    #[test]
    fn test_map_ad_user_organizational_attributes() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        assert_eq!(mapped.attributes["department"], "Engineering");
        assert_eq!(mapped.attributes["job_title"], "Senior Developer");
        assert_eq!(mapped.attributes["company"], "Example Corp");
        assert_eq!(mapped.attributes["employee_id"], "EMP001");
        assert_eq!(mapped.attributes["employee_number"], "12345");
    }

    #[test]
    fn test_map_ad_user_objectguid_base64() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        let expected = base64::engine::general_purpose::STANDARD.encode([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);
        assert_eq!(mapped.external_id, expected);
    }

    #[test]
    fn test_map_ad_user_dn_preserved() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        assert_eq!(mapped.dn, "CN=John Doe,OU=Users,DC=example,DC=com");
        assert_eq!(
            mapped.attributes["dn"],
            "CN=John Doe,OU=Users,DC=example,DC=com"
        );
    }

    #[test]
    fn test_map_ad_user_active_account() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        assert!(mapped.is_active);
        assert_eq!(mapped.uac_value, Some(0x200));
    }

    #[test]
    fn test_map_ad_user_disabled_account() {
        let mut entry = sample_ad_user_entry();
        // NORMAL_ACCOUNT | ACCOUNTDISABLE = 0x202
        entry.set("userAccountControl", AttributeValue::Integer(0x202));

        let mapped = map_ad_user(&entry).unwrap();
        assert!(!mapped.is_active);
        assert_eq!(mapped.uac_value, Some(0x202));
    }

    #[test]
    fn test_map_ad_user_locked_but_active() {
        let mut entry = sample_ad_user_entry();
        // NORMAL_ACCOUNT | LOCKOUT = 0x210 — locked is NOT disabled
        entry.set("userAccountControl", AttributeValue::Integer(0x210));

        let mapped = map_ad_user(&entry).unwrap();
        assert!(mapped.is_active); // locked != disabled
    }

    #[test]
    fn test_map_ad_user_uac_as_string() {
        let mut entry = sample_ad_user_entry();
        // Some LDAP servers return UAC as string
        entry.set("userAccountControl", "514"); // 0x202 = disabled

        let mapped = map_ad_user(&entry).unwrap();
        assert!(!mapped.is_active);
        assert_eq!(mapped.uac_value, Some(514));
    }

    #[test]
    fn test_map_ad_user_no_uac_defaults_active() {
        let mut entry = AttributeSet::new();
        entry.set("objectGUID", AttributeValue::Binary(vec![0x01; 16]));
        entry.set("sAMAccountName", "test");

        let mapped = map_ad_user(&entry).unwrap();
        assert!(mapped.is_active); // Default to active
        assert!(mapped.uac_value.is_none());
    }

    #[test]
    fn test_map_ad_user_manager_dn() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        assert_eq!(
            mapped.attributes["manager_dn"],
            "CN=Jane Boss,OU=Users,DC=example,DC=com"
        );
    }

    #[test]
    fn test_map_ad_user_member_of_multi_valued() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        let member_of = mapped.attributes["member_of_dns"].as_array().unwrap();
        assert_eq!(member_of.len(), 2);
        assert_eq!(
            member_of[0].as_str().unwrap(),
            "CN=Developers,OU=Groups,DC=example,DC=com"
        );
    }

    #[test]
    fn test_map_ad_user_timestamps() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        assert_eq!(mapped.attributes["ad_when_created"], "20240115120000.0Z");
        assert_eq!(mapped.attributes["ad_when_changed"], "20240620153045.0Z");
    }

    #[test]
    fn test_map_ad_user_usn_changed() {
        let entry = sample_ad_user_entry();
        let mapped = map_ad_user(&entry).unwrap();

        assert_eq!(mapped.usn_changed, Some("123456".to_string()));
    }

    #[test]
    fn test_map_ad_user_missing_objectguid_returns_none() {
        let mut entry = AttributeSet::new();
        entry.set("sAMAccountName", "test");
        // No objectGUID

        assert!(map_ad_user(&entry).is_none());
    }

    #[test]
    fn test_map_ad_user_objectguid_as_string() {
        let mut entry = AttributeSet::new();
        entry.set("objectGUID", "some-guid-string");
        entry.set("sAMAccountName", "test");

        let mapped = map_ad_user(&entry).unwrap();
        assert_eq!(mapped.external_id, "some-guid-string");
    }

    #[test]
    fn test_map_ad_user_cn_fallback_display_name() {
        let mut entry = AttributeSet::new();
        entry.set("objectGUID", AttributeValue::Binary(vec![0x01; 16]));
        entry.set("cn", "John Doe");
        // No displayName set

        let mapped = map_ad_user(&entry).unwrap();
        assert_eq!(mapped.attributes["display_name"], "John Doe");
    }

    #[test]
    fn test_map_ad_user_minimal_entry() {
        let mut entry = AttributeSet::new();
        entry.set("objectGUID", AttributeValue::Binary(vec![0xFF; 16]));

        let mapped = map_ad_user(&entry).unwrap();
        assert!(!mapped.external_id.is_empty());
        assert!(mapped.is_active); // Default
        assert!(mapped.attributes.get("username").is_none());
        assert!(mapped.attributes.get("email").is_none());
    }

    // --- T010: Tests for uSNChanged incremental sync ---

    #[test]
    fn test_usn_checkpoint_creation() {
        let cp = UsnCheckpoint::new("123456", "dc01.example.com");
        assert_eq!(cp.usn, "123456");
        assert_eq!(cp.dc, "dc01.example.com");
    }

    #[test]
    fn test_usn_checkpoint_serialization() {
        let cp = UsnCheckpoint::new("123456", "dc01.example.com");
        let token = cp.to_token();

        assert!(token.contains("123456"));
        assert!(token.contains("dc01.example.com"));

        let parsed = UsnCheckpoint::from_token(&token).unwrap();
        assert_eq!(parsed.usn, "123456");
        assert_eq!(parsed.dc, "dc01.example.com");
    }

    #[test]
    fn test_usn_checkpoint_from_invalid_token() {
        assert!(UsnCheckpoint::from_token("not json").is_none());
        assert!(UsnCheckpoint::from_token("").is_none());
    }

    #[test]
    fn test_usn_checkpoint_incremental_filter() {
        let cp = UsnCheckpoint::new("100000", "dc01.example.com");
        let filter =
            cp.incremental_filter("(&(objectClass=user)(objectCategory=person))", "uSNChanged");

        assert!(filter.contains("(&(objectClass=user)(objectCategory=person))"));
        assert!(filter.contains("(uSNChanged>=100000)"));
        // Should exclude the exact USN to avoid reprocessing
        assert!(filter.contains("(!(uSNChanged=100000))"));
    }

    #[test]
    fn test_usn_checkpoint_incremental_filter_with_when_changed() {
        let cp = UsnCheckpoint::new("20240101120000.0Z", "dc01.example.com");
        let filter = cp.incremental_filter("(objectClass=group)", "whenChanged");

        assert!(filter.contains("(whenChanged>=20240101120000.0Z)"));
    }

    #[test]
    fn test_highest_usn_from_batch() {
        let users = vec![
            MappedUser {
                external_id: "a".to_string(),
                dn: "".to_string(),
                attributes: HashMap::new(),
                is_active: true,
                uac_value: None,
                usn_changed: Some("100".to_string()),
            },
            MappedUser {
                external_id: "b".to_string(),
                dn: "".to_string(),
                attributes: HashMap::new(),
                is_active: true,
                uac_value: None,
                usn_changed: Some("300".to_string()),
            },
            MappedUser {
                external_id: "c".to_string(),
                dn: "".to_string(),
                attributes: HashMap::new(),
                is_active: true,
                uac_value: None,
                usn_changed: Some("200".to_string()),
            },
        ];

        assert_eq!(highest_usn(&users), Some("300".to_string()));
    }

    #[test]
    fn test_highest_usn_empty_batch() {
        let users: Vec<MappedUser> = vec![];
        assert_eq!(highest_usn(&users), None);
    }

    #[test]
    fn test_highest_usn_no_usn_values() {
        let users = vec![MappedUser {
            external_id: "a".to_string(),
            dn: "".to_string(),
            attributes: HashMap::new(),
            is_active: true,
            uac_value: None,
            usn_changed: None,
        }];
        assert_eq!(highest_usn(&users), None);
    }

    #[test]
    fn test_build_sync_result_full_sync() {
        let users = vec![MappedUser {
            external_id: "test-guid".to_string(),
            dn: "CN=Test,DC=example,DC=com".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert(
                    "username".to_string(),
                    serde_json::Value::String("testuser".to_string()),
                );
                m
            },
            is_active: true,
            uac_value: Some(0x200),
            usn_changed: Some("500".to_string()),
        }];

        let checkpoint = UsnCheckpoint::new("500", "dc01.example.com");
        let result = build_sync_result(users, SyncChangeType::Create, Some(checkpoint), false);

        assert_eq!(result.changes.len(), 1);
        assert!(!result.has_more);
        assert!(result.new_token.is_some());

        let token = result.new_token.unwrap();
        let parsed = UsnCheckpoint::from_token(&token).unwrap();
        assert_eq!(parsed.usn, "500");
    }

    #[test]
    fn test_build_sync_result_has_more() {
        let result = build_sync_result(vec![], SyncChangeType::Create, None, true);
        assert!(result.has_more);
        assert!(result.new_token.is_none());
    }

    #[test]
    fn test_mapped_user_to_sync_change_create() {
        let user = MappedUser {
            external_id: "guid-123".to_string(),
            dn: "CN=Test,DC=example,DC=com".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert(
                    "username".to_string(),
                    serde_json::Value::String("testuser".to_string()),
                );
                m.insert(
                    "email".to_string(),
                    serde_json::Value::String("test@example.com".to_string()),
                );
                m
            },
            is_active: true,
            uac_value: Some(0x200),
            usn_changed: None,
        };

        let change = mapped_user_to_sync_change(&user, SyncChangeType::Create);
        assert_eq!(change.object_class, "user");
        assert!(matches!(change.change_type, SyncChangeType::Create));

        // Verify attributes are set
        let attrs = change.attributes.as_ref().unwrap();
        assert_eq!(attrs.get_string("username"), Some("testuser"));
        assert_eq!(attrs.get_string("email"), Some("test@example.com"));
        assert_eq!(attrs.get_string("external_id"), Some("guid-123"));
    }

    #[test]
    fn test_mapped_user_to_sync_change_delete() {
        let user = MappedUser {
            external_id: "guid-456".to_string(),
            dn: "".to_string(),
            attributes: HashMap::new(),
            is_active: false,
            uac_value: None,
            usn_changed: None,
        };

        let change = mapped_user_to_sync_change(&user, SyncChangeType::Delete);
        assert!(matches!(change.change_type, SyncChangeType::Delete));
    }

    #[test]
    fn test_user_sync_attributes_list() {
        let attrs = user_sync_attributes();
        assert!(attrs.contains(&"objectGUID"));
        assert!(attrs.contains(&"sAMAccountName"));
        assert!(attrs.contains(&"userPrincipalName"));
        assert!(attrs.contains(&"mail"));
        assert!(attrs.contains(&"displayName"));
        assert!(attrs.contains(&"givenName"));
        assert!(attrs.contains(&"sn"));
        assert!(attrs.contains(&"department"));
        assert!(attrs.contains(&"title"));
        assert!(attrs.contains(&"employeeID"));
        assert!(attrs.contains(&"manager"));
        assert!(attrs.contains(&"userAccountControl"));
        assert!(attrs.contains(&"memberOf"));
        assert!(attrs.contains(&"uSNChanged"));
        assert!(attrs.contains(&"whenCreated"));
        assert!(attrs.contains(&"whenChanged"));
    }

    // --- T014: Tests for manager relationship resolution ---

    fn make_user(external_id: &str, dn: &str, manager_dn: Option<&str>) -> MappedUser {
        let mut attributes = HashMap::new();
        if let Some(mgr) = manager_dn {
            attributes.insert(
                "manager_dn".to_string(),
                serde_json::Value::String(mgr.to_string()),
            );
        }
        MappedUser {
            external_id: external_id.to_string(),
            dn: dn.to_string(),
            attributes,
            is_active: true,
            uac_value: None,
            usn_changed: None,
        }
    }

    #[test]
    fn test_build_dn_lookup() {
        let users = vec![
            make_user("guid-a", "CN=Alice,OU=Users,DC=example,DC=com", None),
            make_user("guid-b", "CN=Bob,OU=Users,DC=example,DC=com", None),
        ];

        let lookup = build_dn_lookup(&users);
        assert_eq!(lookup.len(), 2);
        assert_eq!(
            lookup.get("cn=alice,ou=users,dc=example,dc=com"),
            Some(&"guid-a".to_string())
        );
        assert_eq!(
            lookup.get("cn=bob,ou=users,dc=example,dc=com"),
            Some(&"guid-b".to_string())
        );
    }

    #[test]
    fn test_build_dn_lookup_skips_empty_dn() {
        let users = vec![make_user("guid-a", "", None)];
        let lookup = build_dn_lookup(&users);
        assert!(lookup.is_empty());
    }

    #[test]
    fn test_resolve_manager_references_basic() {
        let mut users = vec![
            make_user(
                "guid-a",
                "CN=Alice,OU=Users,DC=example,DC=com",
                Some("CN=Bob,OU=Users,DC=example,DC=com"),
            ),
            make_user("guid-b", "CN=Bob,OU=Users,DC=example,DC=com", None),
        ];

        let lookup = build_dn_lookup(&users);
        let result = resolve_manager_references(&mut users, &lookup);

        assert_eq!(result.total_with_manager, 1);
        assert_eq!(result.resolved, 1);
        assert_eq!(result.unresolved, 0);
        assert!(result.unresolved_dns.is_empty());

        // Alice should have manager_external_id pointing to Bob
        assert_eq!(
            users[0].attributes.get("manager_external_id"),
            Some(&serde_json::Value::String("guid-b".to_string()))
        );
    }

    #[test]
    fn test_resolve_manager_references_case_insensitive() {
        let mut users = vec![
            make_user(
                "guid-a",
                "CN=Alice,OU=Users,DC=example,DC=com",
                // Manager DN with different case
                Some("cn=bob,ou=Users,DC=EXAMPLE,DC=COM"),
            ),
            make_user("guid-b", "CN=Bob,OU=Users,DC=example,DC=com", None),
        ];

        let lookup = build_dn_lookup(&users);
        let result = resolve_manager_references(&mut users, &lookup);

        assert_eq!(result.resolved, 1);
        assert_eq!(result.unresolved, 0);
    }

    #[test]
    fn test_resolve_manager_references_unresolved() {
        let mut users = vec![make_user(
            "guid-a",
            "CN=Alice,OU=Users,DC=example,DC=com",
            Some("CN=External Manager,OU=Other,DC=example,DC=com"),
        )];

        let lookup = build_dn_lookup(&users);
        let result = resolve_manager_references(&mut users, &lookup);

        assert_eq!(result.total_with_manager, 1);
        assert_eq!(result.resolved, 0);
        assert_eq!(result.unresolved, 1);
        assert_eq!(
            result.unresolved_dns,
            vec!["CN=External Manager,OU=Other,DC=example,DC=com"]
        );

        // manager_external_id should NOT be set
        assert!(users[0].attributes.get("manager_external_id").is_none());
        // manager_dn should still be there
        assert!(users[0].attributes.get("manager_dn").is_some());
    }

    #[test]
    fn test_resolve_manager_references_no_manager() {
        let mut users = vec![
            make_user("guid-a", "CN=Alice,OU=Users,DC=example,DC=com", None),
            make_user("guid-b", "CN=Bob,OU=Users,DC=example,DC=com", None),
        ];

        let lookup = build_dn_lookup(&users);
        let result = resolve_manager_references(&mut users, &lookup);

        assert_eq!(result.total_with_manager, 0);
        assert_eq!(result.resolved, 0);
        assert_eq!(result.unresolved, 0);
    }

    #[test]
    fn test_resolve_manager_references_chain() {
        // Alice → Bob → Charlie (manager chain)
        let mut users = vec![
            make_user(
                "guid-a",
                "CN=Alice,OU=Users,DC=example,DC=com",
                Some("CN=Bob,OU=Users,DC=example,DC=com"),
            ),
            make_user(
                "guid-b",
                "CN=Bob,OU=Users,DC=example,DC=com",
                Some("CN=Charlie,OU=Users,DC=example,DC=com"),
            ),
            make_user("guid-c", "CN=Charlie,OU=Users,DC=example,DC=com", None),
        ];

        let lookup = build_dn_lookup(&users);
        let result = resolve_manager_references(&mut users, &lookup);

        assert_eq!(result.total_with_manager, 2);
        assert_eq!(result.resolved, 2);
        assert_eq!(result.unresolved, 0);

        assert_eq!(
            users[0].attributes["manager_external_id"],
            serde_json::Value::String("guid-b".to_string())
        );
        assert_eq!(
            users[1].attributes["manager_external_id"],
            serde_json::Value::String("guid-c".to_string())
        );
    }

    #[test]
    fn test_resolve_manager_references_mixed() {
        let mut users = vec![
            make_user(
                "guid-a",
                "CN=Alice,OU=Users,DC=example,DC=com",
                Some("CN=Bob,OU=Users,DC=example,DC=com"),
            ),
            make_user("guid-b", "CN=Bob,OU=Users,DC=example,DC=com", None),
            make_user(
                "guid-c",
                "CN=Charlie,OU=Users,DC=example,DC=com",
                Some("CN=Missing,OU=Other,DC=example,DC=com"),
            ),
        ];

        let lookup = build_dn_lookup(&users);
        let result = resolve_manager_references(&mut users, &lookup);

        assert_eq!(result.total_with_manager, 2);
        assert_eq!(result.resolved, 1); // Alice's manager (Bob) resolved
        assert_eq!(result.unresolved, 1); // Charlie's manager missing
    }

    // --- T034: Tests for partial sync resilience ---

    #[test]
    fn test_partial_sync_all_succeed() {
        let entries = vec![
            {
                let mut e = AttributeSet::new();
                e.set("objectGUID", AttributeValue::Binary(vec![0x01; 16]));
                e.set("sAMAccountName", "user1");
                e.set("distinguishedName", "CN=User1,DC=example,DC=com");
                e
            },
            {
                let mut e = AttributeSet::new();
                e.set("objectGUID", AttributeValue::Binary(vec![0x02; 16]));
                e.set("sAMAccountName", "user2");
                e.set("distinguishedName", "CN=User2,DC=example,DC=com");
                e
            },
        ];

        let mut stats = AdSyncStatistics::new("full");
        let users = process_user_batch_resilient(&entries, &mut stats);

        assert_eq!(users.len(), 2);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.skipped, 0);
        assert_eq!(stats.errors, 0);
        assert!(stats.error_details.is_empty());
    }

    #[test]
    fn test_partial_sync_some_fail() {
        // Batch of 3: 2 have objectGUID, 1 missing (will be skipped)
        let entries = vec![
            {
                let mut e = AttributeSet::new();
                e.set("objectGUID", AttributeValue::Binary(vec![0x01; 16]));
                e.set("sAMAccountName", "user1");
                e
            },
            {
                // Missing objectGUID — will be skipped
                let mut e = AttributeSet::new();
                e.set("sAMAccountName", "user2_no_guid");
                e.set("distinguishedName", "CN=User2,DC=example,DC=com");
                e
            },
            {
                let mut e = AttributeSet::new();
                e.set("objectGUID", AttributeValue::Binary(vec![0x03; 16]));
                e.set("sAMAccountName", "user3");
                e
            },
        ];

        let mut stats = AdSyncStatistics::new("full");
        let users = process_user_batch_resilient(&entries, &mut stats);

        assert_eq!(users.len(), 2); // 2 succeeded
        assert_eq!(stats.total, 3);
        assert_eq!(stats.skipped, 1); // 1 skipped (no objectGUID)
        assert_eq!(stats.errors, 0); // skipped != error
    }

    #[test]
    fn test_sync_continues_after_individual_failure() {
        // Even when an entry can't be mapped, subsequent entries are still processed
        let entries = vec![
            {
                let mut e = AttributeSet::new();
                // No objectGUID — skip
                e.set("sAMAccountName", "bad_user");
                e
            },
            {
                let mut e = AttributeSet::new();
                e.set("objectGUID", AttributeValue::Binary(vec![0xAA; 16]));
                e.set("sAMAccountName", "good_user");
                e
            },
        ];

        let mut stats = AdSyncStatistics::new("delta");
        let users = process_user_batch_resilient(&entries, &mut stats);

        // The second (good) entry should still be processed
        assert_eq!(users.len(), 1);
        assert_eq!(
            users[0].attributes.get("username").and_then(|v| v.as_str()),
            Some("good_user")
        );
    }

    #[test]
    fn test_sync_statistics_tracking() {
        let mut stats = AdSyncStatistics::new("full");

        stats.record_success(true); // created
        stats.record_success(true); // created
        stats.record_success(false); // updated
        stats.record_skip();
        stats.record_error("CN=Bad,DC=example,DC=com", "Invalid attribute", "mapping");

        assert_eq!(stats.created, 2);
        assert_eq!(stats.updated, 1);
        assert_eq!(stats.processed, 3);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.errors, 1);
        assert!(stats.has_successes());
        assert_eq!(stats.error_details.len(), 1);
        assert_eq!(stats.error_details[0].dn, "CN=Bad,DC=example,DC=com");
        assert_eq!(stats.error_details[0].phase, "mapping");
    }

    #[test]
    fn test_sync_statistics_json_serialization() {
        let mut stats = AdSyncStatistics::new("delta");
        stats.total = 100;
        stats.processed = 95;
        stats.created = 10;
        stats.updated = 85;
        stats.errors = 5;
        stats.usn_checkpoint = Some("999999".to_string());
        stats.domain_controller = Some("dc01.example.com".to_string());

        let json = stats.to_json();
        assert!(json.is_object());
        assert_eq!(json["sync_type"], "delta");
        assert_eq!(json["total"], 100);
        assert_eq!(json["processed"], 95);
        assert_eq!(json["usn_checkpoint"], "999999");
    }

    #[test]
    fn test_sync_statistics_no_successes() {
        let stats = AdSyncStatistics::new("full");
        assert!(!stats.has_successes());
    }

    // --- T035: Tests for exponential backoff retry ---

    #[test]
    fn test_retry_config_defaults() {
        let config = AdRetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_secs, 1);
        assert_eq!(config.max_delay_secs, 30);
        assert_eq!(config.backoff_multiplier, 2.0);
    }

    #[test]
    fn test_retry_delay_exponential() {
        let config = AdRetryConfig::default();

        // attempt 0: 1 * 2^0 = 1s
        assert_eq!(
            config.delay_for_attempt(0),
            std::time::Duration::from_secs(1)
        );
        // attempt 1: 1 * 2^1 = 2s
        assert_eq!(
            config.delay_for_attempt(1),
            std::time::Duration::from_secs(2)
        );
        // attempt 2: 1 * 2^2 = 4s
        assert_eq!(
            config.delay_for_attempt(2),
            std::time::Duration::from_secs(4)
        );
        // attempt 3: 1 * 2^3 = 8s
        assert_eq!(
            config.delay_for_attempt(3),
            std::time::Duration::from_secs(8)
        );
    }

    #[test]
    fn test_retry_delay_capped() {
        let config = AdRetryConfig {
            max_delay_secs: 10,
            initial_delay_secs: 1,
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        // attempt 5: 1 * 2^5 = 32s, but capped at 10s
        assert_eq!(
            config.delay_for_attempt(5),
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    fn test_retry_should_retry() {
        let config = AdRetryConfig {
            max_retries: 3,
            ..Default::default()
        };

        assert!(config.should_retry(0));
        assert!(config.should_retry(1));
        assert!(config.should_retry(2));
        assert!(!config.should_retry(3)); // max reached
        assert!(!config.should_retry(4));
    }

    #[test]
    fn test_retry_all_exhausted() {
        let config = AdRetryConfig {
            max_retries: 0,
            ..Default::default()
        };

        // With 0 retries, even the first attempt should not retry
        assert!(!config.should_retry(0));
    }
}
