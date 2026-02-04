//! IP restriction service (F028).
//!
//! Handles IP-based access control with whitelist/blacklist modes,
//! CIDR validation, scope-based filtering, and caching.

use crate::error::ApiAuthError;
use crate::models::{
    CreateIpRuleRequest, IpRuleResponse, IpSettingsResponse, ListRulesQuery, MatchingRuleInfo,
    UpdateIpRuleRequest, UpdateIpSettingsRequest, ValidateIpResponse,
};
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_db::models::{
    CreateIpRule, IpEnforcementMode, IpRestrictionRule, IpRuleType, ListRulesFilter,
    TenantIpSettings, UpdateIpRule, UpdateIpSettings,
};
use xavyo_db::set_tenant_context;

// ============================================================================
// Standalone CIDR Helper Functions
// ============================================================================

/// Validate CIDR notation (standalone function for testing).
pub fn validate_cidr(cidr: &str) -> Result<(), ApiAuthError> {
    cidr.parse::<IpNetwork>()
        .map_err(|e| ApiAuthError::InvalidCidr(format!("{cidr}: {e}")))?;
    Ok(())
}

/// Check if an IP address matches a CIDR (standalone function for testing).
pub fn ip_matches_cidr(ip: &IpAddr, cidr: &str) -> bool {
    if let Ok(network) = cidr.parse::<IpNetwork>() {
        network.contains(*ip)
    } else {
        warn!(cidr = %cidr, "Invalid CIDR in database");
        false
    }
}

/// Default cache TTL in seconds.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300; // 5 minutes

/// Cached IP restriction data for a tenant.
#[derive(Debug, Clone)]
struct CachedData {
    settings: TenantIpSettings,
    rules: Vec<IpRestrictionRule>,
    cached_at: Instant,
}

/// IP restriction cache.
#[derive(Debug, Default)]
struct IpRestrictionCache {
    data: HashMap<Uuid, CachedData>,
    ttl: Duration,
}

impl IpRestrictionCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            data: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn get(&self, tenant_id: &Uuid) -> Option<&CachedData> {
        self.data
            .get(tenant_id)
            .filter(|d| d.cached_at.elapsed() < self.ttl)
    }

    fn set(&mut self, tenant_id: Uuid, settings: TenantIpSettings, rules: Vec<IpRestrictionRule>) {
        self.data.insert(
            tenant_id,
            CachedData {
                settings,
                rules,
                cached_at: Instant::now(),
            },
        );
    }

    fn invalidate(&mut self, tenant_id: &Uuid) {
        self.data.remove(tenant_id);
    }
}

/// IP restriction service.
#[derive(Clone)]
pub struct IpRestrictionService {
    pool: PgPool,
    cache: Arc<RwLock<IpRestrictionCache>>,
}

impl IpRestrictionService {
    /// Create a new IP restriction service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(IpRestrictionCache::new(DEFAULT_CACHE_TTL_SECS))),
        }
    }

    /// Create with custom cache TTL.
    #[must_use] 
    pub fn with_cache_ttl(pool: PgPool, ttl_secs: u64) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(IpRestrictionCache::new(ttl_secs))),
        }
    }

    // ========================================================================
    // Settings Operations
    // ========================================================================

    /// Get IP restriction settings for a tenant.
    pub async fn get_settings(&self, tenant_id: Uuid) -> Result<IpSettingsResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let settings = TenantIpSettings::get_or_default(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(settings.into())
    }

    /// Update IP restriction settings for a tenant.
    pub async fn update_settings(
        &self,
        tenant_id: Uuid,
        request: UpdateIpSettingsRequest,
        updated_by: Option<Uuid>,
    ) -> Result<IpSettingsResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let update_data = UpdateIpSettings {
            enforcement_mode: request.enforcement_mode,
            bypass_for_super_admin: request.bypass_for_super_admin,
        };

        let settings = TenantIpSettings::upsert(&mut *conn, tenant_id, update_data, updated_by)
            .await
            .map_err(ApiAuthError::Database)?;

        // Invalidate cache
        self.invalidate_cache(tenant_id).await;

        info!(
            tenant_id = %tenant_id,
            mode = %settings.enforcement_mode,
            "IP restriction settings updated"
        );

        Ok(settings.into())
    }

    // ========================================================================
    // Rule Operations
    // ========================================================================

    /// Create a new IP restriction rule.
    pub async fn create_rule(
        &self,
        tenant_id: Uuid,
        request: CreateIpRuleRequest,
        created_by: Option<Uuid>,
    ) -> Result<IpRuleResponse, ApiAuthError> {
        // Validate CIDR
        validate_cidr(&request.ip_cidr)?;

        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Check for duplicate name
        let name_exists =
            IpRestrictionRule::name_exists(&mut *conn, tenant_id, &request.name, None)
                .await
                .map_err(ApiAuthError::Database)?;

        if name_exists {
            return Err(ApiAuthError::RuleNameExists);
        }

        let create_data = CreateIpRule {
            rule_type: request.rule_type,
            scope: Some(request.scope),
            ip_cidr: request.ip_cidr,
            name: request.name,
            description: request.description,
            is_active: Some(request.is_active),
        };

        let rule = IpRestrictionRule::create(&mut *conn, tenant_id, create_data, created_by)
            .await
            .map_err(ApiAuthError::Database)?;

        // Invalidate cache
        self.invalidate_cache(tenant_id).await;

        info!(
            tenant_id = %tenant_id,
            rule_id = %rule.id,
            rule_type = %rule.rule_type,
            cidr = %rule.ip_cidr,
            "IP restriction rule created"
        );

        Ok(rule.into())
    }

    /// List IP restriction rules for a tenant.
    pub async fn list_rules(
        &self,
        tenant_id: Uuid,
        query: ListRulesQuery,
    ) -> Result<Vec<IpRuleResponse>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let filter = ListRulesFilter {
            is_active: query.is_active,
            rule_type: query.rule_type,
        };

        let rules = IpRestrictionRule::list(&mut *conn, tenant_id, filter)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(rules.into_iter().map(Into::into).collect())
    }

    /// Get a specific IP restriction rule.
    pub async fn get_rule(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<IpRuleResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let rule = IpRestrictionRule::find_by_id(&mut *conn, tenant_id, rule_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::RuleNotFound)?;

        Ok(rule.into())
    }

    /// Update an IP restriction rule.
    pub async fn update_rule(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        request: UpdateIpRuleRequest,
    ) -> Result<IpRuleResponse, ApiAuthError> {
        // Validate CIDR if provided
        if let Some(ref cidr) = request.ip_cidr {
            validate_cidr(cidr)?;
        }

        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Check for duplicate name if updating name
        if let Some(ref name) = request.name {
            let name_exists =
                IpRestrictionRule::name_exists(&mut *conn, tenant_id, name, Some(rule_id))
                    .await
                    .map_err(ApiAuthError::Database)?;

            if name_exists {
                return Err(ApiAuthError::RuleNameExists);
            }
        }

        let update_data = UpdateIpRule {
            rule_type: request.rule_type,
            scope: request.scope,
            ip_cidr: request.ip_cidr,
            name: request.name,
            description: request.description,
            is_active: request.is_active,
        };

        let rule = IpRestrictionRule::update(&mut *conn, tenant_id, rule_id, update_data)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::RuleNotFound)?;

        // Invalidate cache
        self.invalidate_cache(tenant_id).await;

        info!(
            tenant_id = %tenant_id,
            rule_id = %rule.id,
            "IP restriction rule updated"
        );

        Ok(rule.into())
    }

    /// Delete an IP restriction rule.
    pub async fn delete_rule(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let deleted = IpRestrictionRule::delete(&mut *conn, tenant_id, rule_id)
            .await
            .map_err(ApiAuthError::Database)?;

        if !deleted {
            return Err(ApiAuthError::RuleNotFound);
        }

        // Invalidate cache
        self.invalidate_cache(tenant_id).await;

        info!(
            tenant_id = %tenant_id,
            rule_id = %rule_id,
            "IP restriction rule deleted"
        );

        Ok(())
    }

    // ========================================================================
    // IP Validation & Filtering
    // ========================================================================

    /// Check if an IP address is allowed access for a tenant.
    ///
    /// Returns Ok(()) if access is allowed, Err(IpBlocked) if blocked.
    pub async fn check_ip_access(
        &self,
        tenant_id: Uuid,
        ip_address: &str,
        user_roles: &[String],
        is_super_admin: bool,
    ) -> Result<(), ApiAuthError> {
        // Parse IP address
        let ip: IpAddr = ip_address
            .parse()
            .map_err(|_| ApiAuthError::Validation(format!("Invalid IP address: {ip_address}")))?;

        // Get cached or fresh data
        let (settings, rules) = self.get_cached_data(tenant_id).await?;

        // Check enforcement mode
        match settings.enforcement_mode {
            IpEnforcementMode::Disabled => {
                // No restrictions
                Ok(())
            }
            IpEnforcementMode::Whitelist => {
                // Super admin bypass
                if is_super_admin && settings.bypass_for_super_admin {
                    return Ok(());
                }

                // Filter to whitelist rules that apply to this user
                let matching_rules: Vec<_> = rules
                    .iter()
                    .filter(|r| r.rule_type == IpRuleType::Whitelist && r.is_active)
                    .filter(|r| r.scope_applies(user_roles))
                    .filter(|r| ip_matches_cidr(&ip, &r.ip_cidr))
                    .collect();

                if matching_rules.is_empty() {
                    // Get applicable rules for error message
                    let applicable_rules: Vec<_> = rules
                        .iter()
                        .filter(|r| r.rule_type == IpRuleType::Whitelist && r.is_active)
                        .filter(|r| r.scope_applies(user_roles))
                        .collect();

                    let reason = if applicable_rules.is_empty() {
                        format!(
                            "Access denied: No whitelist rules configured, all IPs are blocked (your IP: {ip_address})"
                        )
                    } else {
                        format!(
                            "Access denied: Your IP address ({ip_address}) is not allowed to access this tenant"
                        )
                    };

                    return Err(ApiAuthError::IpBlocked(reason));
                }

                Ok(())
            }
            IpEnforcementMode::Blacklist => {
                // Super admin bypass
                if is_super_admin && settings.bypass_for_super_admin {
                    return Ok(());
                }

                // Filter to blacklist rules that apply to this user
                let matching_rules: Vec<_> = rules
                    .iter()
                    .filter(|r| r.rule_type == IpRuleType::Blacklist && r.is_active)
                    .filter(|r| r.scope_applies(user_roles))
                    .filter(|r| ip_matches_cidr(&ip, &r.ip_cidr))
                    .collect();

                if !matching_rules.is_empty() {
                    let rule_name = &matching_rules[0].name;
                    return Err(ApiAuthError::IpBlocked(format!(
                        "Access denied: Your IP address ({ip_address}) is blocked by rule '{rule_name}'"
                    )));
                }

                Ok(())
            }
        }
    }

    /// Validate an IP address against current rules (for admin testing).
    pub async fn validate_ip(
        &self,
        tenant_id: Uuid,
        ip_address: &str,
        role: Option<&str>,
    ) -> Result<ValidateIpResponse, ApiAuthError> {
        // Parse IP address
        let ip: IpAddr = ip_address
            .parse()
            .map_err(|_| ApiAuthError::Validation(format!("Invalid IP address: {ip_address}")))?;

        // Get data
        let (settings, rules) = self.get_cached_data(tenant_id).await?;

        // Build user roles for testing
        let user_roles: Vec<String> = role.map(|r| vec![r.to_string()]).unwrap_or_default();

        // Find matching rules
        let matching_rules: Vec<MatchingRuleInfo> = rules
            .iter()
            .filter(|r| r.is_active)
            .filter(|r| r.scope_applies(&user_roles))
            .filter(|r| ip_matches_cidr(&ip, &r.ip_cidr))
            .map(|r| MatchingRuleInfo {
                id: r.id,
                name: r.name.clone(),
                ip_cidr: r.ip_cidr.clone(),
            })
            .collect();

        let (status, reason) = match settings.enforcement_mode {
            IpEnforcementMode::Disabled => (
                "disabled".to_string(),
                "IP restrictions are disabled".to_string(),
            ),
            IpEnforcementMode::Whitelist => {
                let whitelist_matches: Vec<_> = matching_rules
                    .iter()
                    .filter(|_| {
                        rules
                            .iter()
                            .any(|r| r.rule_type == IpRuleType::Whitelist && r.is_active)
                    })
                    .collect();

                if whitelist_matches.is_empty() {
                    let has_any_whitelist = rules.iter().any(|r| {
                        r.rule_type == IpRuleType::Whitelist
                            && r.is_active
                            && r.scope_applies(&user_roles)
                    });

                    if has_any_whitelist {
                        (
                            "blocked".to_string(),
                            "IP does not match any whitelist rule".to_string(),
                        )
                    } else {
                        (
                            "blocked".to_string(),
                            "No whitelist rules configured, all IPs are blocked".to_string(),
                        )
                    }
                } else {
                    (
                        "allowed".to_string(),
                        format!("IP matches whitelist rule '{}'", whitelist_matches[0].name),
                    )
                }
            }
            IpEnforcementMode::Blacklist => {
                let blacklist_matches: Vec<_> = matching_rules
                    .iter()
                    .filter(|m| {
                        rules
                            .iter()
                            .any(|r| r.id == m.id && r.rule_type == IpRuleType::Blacklist)
                    })
                    .collect();

                if blacklist_matches.is_empty() {
                    (
                        "allowed".to_string(),
                        "IP does not match any blacklist rule".to_string(),
                    )
                } else {
                    (
                        "blocked".to_string(),
                        format!("IP matches blacklist rule '{}'", blacklist_matches[0].name),
                    )
                }
            }
        };

        Ok(ValidateIpResponse {
            ip_address: ip_address.to_string(),
            status,
            enforcement_mode: settings.enforcement_mode,
            matching_rules,
            reason,
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Validate CIDR notation (delegates to standalone function).
    pub fn validate_cidr_str(&self, cidr: &str) -> Result<(), ApiAuthError> {
        validate_cidr(cidr)
    }

    /// Get cached settings and rules, or fetch from database.
    async fn get_cached_data(
        &self,
        tenant_id: Uuid,
    ) -> Result<(TenantIpSettings, Vec<IpRestrictionRule>), ApiAuthError> {
        // Try cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&tenant_id) {
                return Ok((cached.settings.clone(), cached.rules.clone()));
            }
        }

        // Fetch from database
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let settings = TenantIpSettings::get_or_default(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Fetch all active rules (both types)
        let whitelist_rules =
            IpRestrictionRule::list_active(&mut *conn, tenant_id, IpRuleType::Whitelist)
                .await
                .map_err(ApiAuthError::Database)?;

        let blacklist_rules =
            IpRestrictionRule::list_active(&mut *conn, tenant_id, IpRuleType::Blacklist)
                .await
                .map_err(ApiAuthError::Database)?;

        let mut rules = whitelist_rules;
        rules.extend(blacklist_rules);

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.set(tenant_id, settings.clone(), rules.clone());
        }

        Ok((settings, rules))
    }

    /// Invalidate cache for a tenant.
    async fn invalidate_cache(&self, tenant_id: Uuid) {
        let mut cache = self.cache.write().await;
        cache.invalidate(&tenant_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cidr_ipv4() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("0.0.0.0/0").is_ok());
        assert!(validate_cidr("192.168.1.1/32").is_ok());
        assert!(validate_cidr("invalid").is_err());
        assert!(validate_cidr("192.168.1.0/33").is_err());
    }

    #[test]
    fn test_validate_cidr_ipv6() {
        assert!(validate_cidr("2001:db8::/32").is_ok());
        assert!(validate_cidr("::1/128").is_ok());
        assert!(validate_cidr("::/0").is_ok());
        assert!(validate_cidr("2001:db8::1/128").is_ok());
        assert!(validate_cidr("2001:db8::/129").is_err());
    }

    #[test]
    fn test_ip_matches_cidr_ipv4() {
        let ip1: IpAddr = "192.168.1.50".parse().unwrap();
        let ip2: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(ip_matches_cidr(&ip1, "192.168.1.0/24"));
        assert!(ip_matches_cidr(&ip1, "192.168.0.0/16"));
        assert!(!ip_matches_cidr(&ip1, "192.168.2.0/24"));
        assert!(!ip_matches_cidr(&ip2, "192.168.1.0/24"));
        assert!(ip_matches_cidr(&ip2, "10.0.0.0/8"));
    }

    #[test]
    fn test_ip_matches_cidr_ipv6() {
        let ip1: IpAddr = "2001:db8::1".parse().unwrap();
        let ip2: IpAddr = "2001:db9::1".parse().unwrap();

        assert!(ip_matches_cidr(&ip1, "2001:db8::/32"));
        assert!(!ip_matches_cidr(&ip2, "2001:db8::/32"));
        assert!(ip_matches_cidr(&ip1, "::/0")); // Match all
    }

    #[test]
    fn test_cache_ttl() {
        let mut cache = IpRestrictionCache::new(1); // 1 second TTL
        let tenant_id = Uuid::new_v4();
        let settings = TenantIpSettings::default_for_tenant(tenant_id);
        let rules = vec![];

        cache.set(tenant_id, settings, rules);
        assert!(cache.get(&tenant_id).is_some());

        // Simulate TTL expiration
        std::thread::sleep(Duration::from_secs(2));
        assert!(cache.get(&tenant_id).is_none());
    }
}
