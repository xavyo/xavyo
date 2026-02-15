//! JWT claims structure with standard and custom claims.
//!
//! Provides the `JwtClaims` struct containing both RFC 7519 standard claims
//! and Xavyo-specific custom claims (`tenant_id`, roles).

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_core::TenantId;

/// Maximum allowed nesting depth for actor claim chains.
/// Prevents stack overflow from deeply nested `act` claims during deserialization.
pub const MAX_ACTOR_CHAIN_DEPTH: usize = 10;

/// RFC 8693 actor claim — identifies who is acting on behalf of the subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActorClaim {
    /// Subject identifier of the actor (NHI ID).
    pub sub: String,
    /// NHI type of the actor (e.g., "agent").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nhi_type: Option<String>,
    /// Nested actor for multi-hop delegation chains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActorClaim>>,
}

impl ActorClaim {
    /// Returns the nesting depth of this actor claim chain.
    pub fn chain_depth(&self) -> usize {
        let mut depth = 1;
        let mut current = self.act.as_deref();
        while let Some(actor) = current {
            depth += 1;
            current = actor.act.as_deref();
        }
        depth
    }

    /// Validates that the chain depth does not exceed the maximum.
    /// Returns `Err` with a message if the chain is too deep.
    pub fn validate_depth(&self) -> Result<(), String> {
        let depth = self.chain_depth();
        if depth > MAX_ACTOR_CHAIN_DEPTH {
            Err(format!(
                "actor claim chain depth {depth} exceeds maximum {MAX_ACTOR_CHAIN_DEPTH}"
            ))
        } else {
            Ok(())
        }
    }
}

/// JWT claims containing standard and custom claims.
///
/// # Standard Claims (RFC 7519)
///
/// - `sub`: Subject (typically user ID)
/// - `iss`: Issuer (who created the token)
/// - `aud`: Audience (intended recipients)
/// - `exp`: Expiration time (Unix timestamp)
/// - `iat`: Issued at (Unix timestamp)
/// - `jti`: JWT ID (unique identifier)
///
/// # Custom Claims (Xavyo-specific)
///
/// - `tid`: Tenant ID (for multi-tenant isolation)
/// - `roles`: User roles for authorization
///
/// # Example
///
/// ```rust
/// use xavyo_auth::JwtClaims;
/// use xavyo_core::TenantId;
///
/// let claims = JwtClaims::builder()
///     .subject("user-123")
///     .issuer("xavyo")
///     .audience(vec!["xavyo-api"])
///     .tenant_id(TenantId::new())
///     .roles(vec!["admin", "user"])
///     .expires_in_secs(3600)
///     .build();
///
/// assert_eq!(claims.sub, "user-123");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtClaims {
    /// Subject - typically the user ID.
    pub sub: String,

    /// Issuer - who created the token.
    pub iss: String,

    /// Audience - intended recipients.
    #[serde(default)]
    pub aud: Vec<String>,

    /// Expiration time as Unix timestamp.
    pub exp: i64,

    /// Issued at as Unix timestamp.
    pub iat: i64,

    /// JWT ID - unique identifier for this token.
    pub jti: String,

    /// Tenant ID for multi-tenant isolation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<Uuid>,

    /// User roles for authorization.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Token purpose (e.g., "`mfa_verification`" for partial tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// User email address (optional, included in user tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    // Power of Attorney claims (F-061)
    /// PoA grant ID when acting on behalf of another user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acting_as_poa_id: Option<Uuid>,

    /// User ID of the donor when acting on their behalf.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acting_as_user_id: Option<Uuid>,

    /// Session ID of the assumed identity session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acting_as_session_id: Option<Uuid>,

    /// OAuth2 scopes granted to this token (space-separated in RFC 9068).
    /// Present on delegated tokens to make scope enforcement self-contained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    // RFC 8693 Token Exchange delegation claims
    /// Actor claim (RFC 8693) — who is actually performing the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,

    /// Delegation grant ID for audit correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<Uuid>,

    /// Current delegation depth (1 = direct, 2+ = chained).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_depth: Option<i32>,
}

impl JwtClaims {
    /// Create a new builder for constructing JWT claims.
    #[must_use]
    pub fn builder() -> JwtClaimsBuilder {
        JwtClaimsBuilder::default()
    }

    /// Check if the token is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Get the tenant ID if present.
    #[must_use]
    pub fn tenant_id(&self) -> Option<TenantId> {
        self.tid.map(TenantId::from_uuid)
    }

    /// Check if the claims contain a specific role.
    ///
    /// Role hierarchy: `super_admin` implies `admin`.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
            || (role == "admin" && self.roles.iter().any(|r| r == "super_admin"))
    }

    /// Check if the claims contain any of the specified roles.
    #[must_use]
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.has_role(r))
    }

    /// Check if the token represents an assumed identity (F-061).
    #[must_use]
    pub fn is_acting_as(&self) -> bool {
        self.acting_as_poa_id.is_some()
            && self.acting_as_user_id.is_some()
            && self.acting_as_session_id.is_some()
    }

    /// Get the actual actor's user ID (F-061).
    ///
    /// If acting on behalf of someone, returns the attorney's ID (sub).
    /// Otherwise returns the user's own ID (sub).
    #[must_use]
    pub fn actual_actor_id(&self) -> &str {
        &self.sub
    }

    /// Get the effective user ID (F-061).
    ///
    /// If acting on behalf of someone, returns the donor's ID.
    /// Otherwise returns the user's own ID (sub).
    #[must_use]
    pub fn effective_user_id(&self) -> Option<Uuid> {
        if self.is_acting_as() {
            self.acting_as_user_id
        } else {
            self.sub.parse().ok()
        }
    }

    /// Check if this is a delegated token (RFC 8693).
    #[must_use]
    pub fn is_delegated(&self) -> bool {
        self.act.is_some()
    }

    /// Get the actual actor NHI ID (the agent doing the work).
    #[must_use]
    pub fn actor_nhi_id(&self) -> Option<Uuid> {
        self.act.as_ref().and_then(|a| Uuid::parse_str(&a.sub).ok())
    }

    /// Get the full delegation chain as a list of actor subject IDs.
    #[must_use]
    pub fn delegation_chain(&self) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = self.act.as_ref();
        while let Some(actor) = current {
            chain.push(actor.sub.clone());
            current = actor.act.as_deref();
        }
        chain
    }
}

/// Builder for constructing JWT claims.
#[derive(Debug, Default)]
pub struct JwtClaimsBuilder {
    sub: Option<String>,
    iss: Option<String>,
    aud: Vec<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    jti: Option<String>,
    tid: Option<Uuid>,
    roles: Vec<String>,
    purpose: Option<String>,
    email: Option<String>,
    // Power of Attorney fields (F-061)
    acting_as_poa_id: Option<Uuid>,
    acting_as_user_id: Option<Uuid>,
    acting_as_session_id: Option<Uuid>,
    // OAuth2 scope
    scope: Option<String>,
    // RFC 8693 Token Exchange delegation fields
    act: Option<ActorClaim>,
    delegation_id: Option<Uuid>,
    delegation_depth: Option<i32>,
}

impl JwtClaimsBuilder {
    /// Set the subject (user ID).
    #[must_use]
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Set the issuer.
    #[must_use]
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the audience.
    #[must_use]
    pub fn audience(mut self, aud: Vec<impl Into<String>>) -> Self {
        self.aud = aud.into_iter().map(Into::into).collect();
        self
    }

    /// Set expiration time as Unix timestamp.
    #[must_use]
    pub fn expiration(mut self, exp: i64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Set expiration time as seconds from now.
    #[must_use]
    pub fn expires_in_secs(mut self, secs: i64) -> Self {
        self.exp = Some(Utc::now().timestamp() + secs);
        self
    }

    /// Set expiration time using a Duration.
    #[must_use]
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.exp = Some((Utc::now() + duration).timestamp());
        self
    }

    /// Set the issued at time.
    #[must_use]
    pub fn issued_at(mut self, iat: i64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// Set the JWT ID.
    #[must_use]
    pub fn jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Set the tenant ID.
    #[must_use]
    pub fn tenant_id(mut self, tid: TenantId) -> Self {
        self.tid = Some(*tid.as_uuid());
        self
    }

    /// Set the tenant ID from a UUID.
    #[must_use]
    pub fn tenant_uuid(mut self, tid: Uuid) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Set the roles.
    #[must_use]
    pub fn roles(mut self, roles: Vec<impl Into<String>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Add a single role.
    #[must_use]
    pub fn add_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Set the token purpose (e.g., "`mfa_verification`").
    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    /// Set the user's email address.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the Power of Attorney grant ID for identity assumption (F-061).
    #[must_use]
    pub fn acting_as_poa_id(mut self, poa_id: Uuid) -> Self {
        self.acting_as_poa_id = Some(poa_id);
        self
    }

    /// Set the donor's user ID when acting on their behalf (F-061).
    #[must_use]
    pub fn acting_as_user_id(mut self, user_id: Uuid) -> Self {
        self.acting_as_user_id = Some(user_id);
        self
    }

    /// Set the assumed identity session ID (F-061).
    #[must_use]
    pub fn acting_as_session_id(mut self, session_id: Uuid) -> Self {
        self.acting_as_session_id = Some(session_id);
        self
    }

    /// Set all acting_as fields for identity assumption (F-061).
    #[must_use]
    pub fn acting_as(mut self, poa_id: Uuid, user_id: Uuid, session_id: Uuid) -> Self {
        self.acting_as_poa_id = Some(poa_id);
        self.acting_as_user_id = Some(user_id);
        self.acting_as_session_id = Some(session_id);
        self
    }

    /// Set the OAuth2 scope (space-separated string, per RFC 9068).
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Set the actor claim (RFC 8693) for delegation.
    #[must_use]
    pub fn act(mut self, act: ActorClaim) -> Self {
        self.act = Some(act);
        self
    }

    /// Set the delegation grant ID for audit correlation.
    #[must_use]
    pub fn delegation_id(mut self, id: Uuid) -> Self {
        self.delegation_id = Some(id);
        self
    }

    /// Set the current delegation depth.
    #[must_use]
    pub fn delegation_depth(mut self, depth: i32) -> Self {
        self.delegation_depth = Some(depth);
        self
    }

    /// Build the JWT claims.
    ///
    /// # Defaults
    ///
    /// - `sub`: Empty string if not set
    /// - `iss`: "xavyo" if not set
    /// - `aud`: Empty vec if not set
    /// - `exp`: 1 hour from now if not set
    /// - `iat`: Current time if not set
    /// - `jti`: New UUID v4 if not set
    #[must_use]
    pub fn build(self) -> JwtClaims {
        let now = Utc::now().timestamp();

        JwtClaims {
            sub: self.sub.unwrap_or_default(),
            iss: self.iss.unwrap_or_else(|| "xavyo".to_string()),
            aud: self.aud,
            exp: self.exp.unwrap_or(now + 3600), // Default: 1 hour
            iat: self.iat.unwrap_or(now),
            jti: self.jti.unwrap_or_else(|| Uuid::new_v4().to_string()),
            tid: self.tid,
            roles: self.roles,
            purpose: self.purpose,
            email: self.email,
            scope: self.scope,
            acting_as_poa_id: self.acting_as_poa_id,
            acting_as_user_id: self.acting_as_user_id,
            acting_as_session_id: self.acting_as_session_id,
            act: self.act,
            delegation_id: self.delegation_id,
            delegation_depth: self.delegation_depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_builder_basic() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("test-issuer")
            .build();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.iss, "test-issuer");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_claims_builder_with_tenant() {
        let tenant_id = TenantId::new();
        let claims = JwtClaims::builder()
            .subject("user-123")
            .tenant_id(tenant_id)
            .build();

        assert_eq!(claims.tenant_id(), Some(tenant_id));
    }

    #[test]
    fn test_claims_builder_with_roles() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .roles(vec!["admin", "user"])
            .build();

        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
        assert!(!claims.has_role("superadmin"));
    }

    #[test]
    fn test_super_admin_implies_admin() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .roles(vec!["super_admin"])
            .build();

        assert!(claims.has_role("super_admin"));
        assert!(claims.has_role("admin")); // super_admin implies admin
        assert!(!claims.has_role("member"));
    }

    #[test]
    fn test_claims_has_any_role() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .roles(vec!["admin"])
            .build();

        assert!(claims.has_any_role(&["admin", "user"]));
        assert!(!claims.has_any_role(&["superadmin", "moderator"]));
    }

    #[test]
    fn test_claims_expiration() {
        // Token expiring in 1 hour
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expires_in_secs(3600)
            .build();

        assert!(!claims.is_expired());

        // Token that expired 1 hour ago
        let claims = JwtClaims::builder()
            .subject("user-123")
            .expiration(Utc::now().timestamp() - 3600)
            .build();

        assert!(claims.is_expired());
    }

    #[test]
    fn test_claims_serialization() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .issuer("xavyo")
            .audience(vec!["xavyo-api"])
            .roles(vec!["admin"])
            .build();

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: JwtClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.iss, deserialized.iss);
        assert_eq!(claims.roles, deserialized.roles);
    }

    #[test]
    fn test_claims_without_tenant_serialization() {
        let claims = JwtClaims::builder().subject("user-123").build();

        let json = serde_json::to_string(&claims).unwrap();

        // tid should not be present in JSON when None
        assert!(!json.contains("tid"));
    }

    #[test]
    fn test_claims_add_role() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .add_role("admin")
            .add_role("user")
            .build();

        assert_eq!(claims.roles.len(), 2);
        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
    }

    #[test]
    fn test_claims_acting_as() {
        let poa_id = Uuid::new_v4();
        let donor_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let claims = JwtClaims::builder()
            .subject("attorney-123")
            .acting_as(poa_id, donor_id, session_id)
            .build();

        assert!(claims.is_acting_as());
        assert_eq!(claims.acting_as_poa_id, Some(poa_id));
        assert_eq!(claims.acting_as_user_id, Some(donor_id));
        assert_eq!(claims.acting_as_session_id, Some(session_id));
        assert_eq!(claims.actual_actor_id(), "attorney-123");
        assert_eq!(claims.effective_user_id(), Some(donor_id));
    }

    #[test]
    fn test_claims_not_acting_as() {
        let user_id = Uuid::new_v4();
        let claims = JwtClaims::builder().subject(user_id.to_string()).build();

        assert!(!claims.is_acting_as());
        assert_eq!(claims.actual_actor_id(), &user_id.to_string());
        assert_eq!(claims.effective_user_id(), Some(user_id));
    }

    #[test]
    fn test_acting_as_claims_not_serialized_when_none() {
        let claims = JwtClaims::builder().subject("user-123").build();

        let json = serde_json::to_string(&claims).unwrap();

        // acting_as fields should not be present in JSON when None
        assert!(!json.contains("acting_as_poa_id"));
        assert!(!json.contains("acting_as_user_id"));
        assert!(!json.contains("acting_as_session_id"));
    }

    #[test]
    fn test_actor_claim_serialization() {
        let actor = ActorClaim {
            sub: "agent-001".to_string(),
            nhi_type: Some("agent".to_string()),
            act: Some(Box::new(ActorClaim {
                sub: "agent-000".to_string(),
                nhi_type: None,
                act: None,
            })),
        };

        let json = serde_json::to_string(&actor).unwrap();
        let deserialized: ActorClaim = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.sub, "agent-001");
        assert_eq!(deserialized.nhi_type, Some("agent".to_string()));
        assert!(deserialized.act.is_some());
        assert_eq!(deserialized.act.as_ref().unwrap().sub, "agent-000");
        assert_eq!(deserialized.act.as_ref().unwrap().nhi_type, None);
        assert!(deserialized.act.as_ref().unwrap().act.is_none());
    }

    #[test]
    fn test_claims_delegation() {
        let agent_id = Uuid::new_v4();
        let delegation_id = Uuid::new_v4();
        let actor = ActorClaim {
            sub: agent_id.to_string(),
            nhi_type: Some("agent".to_string()),
            act: None,
        };

        let claims = JwtClaims::builder()
            .subject("user-123")
            .act(actor)
            .delegation_id(delegation_id)
            .delegation_depth(1)
            .build();

        assert!(claims.is_delegated());
        assert_eq!(claims.actor_nhi_id(), Some(agent_id));
        assert_eq!(claims.delegation_id, Some(delegation_id));
        assert_eq!(claims.delegation_depth, Some(1));
        assert_eq!(claims.delegation_chain(), vec![agent_id.to_string()]);
    }

    #[test]
    fn test_delegation_claims_not_serialized_when_none() {
        let claims = JwtClaims::builder().subject("user-123").build();

        let json = serde_json::to_string(&claims).unwrap();

        assert!(!json.contains("\"act\""));
        assert!(!json.contains("delegation_id"));
        assert!(!json.contains("delegation_depth"));
    }

    #[test]
    fn test_actor_claim_chain_depth() {
        // Single actor: depth 1
        let single = ActorClaim {
            sub: "a".to_string(),
            nhi_type: None,
            act: None,
        };
        assert_eq!(single.chain_depth(), 1);
        assert!(single.validate_depth().is_ok());

        // Chain of 3
        let chain = ActorClaim {
            sub: "a".to_string(),
            nhi_type: None,
            act: Some(Box::new(ActorClaim {
                sub: "b".to_string(),
                nhi_type: None,
                act: Some(Box::new(ActorClaim {
                    sub: "c".to_string(),
                    nhi_type: None,
                    act: None,
                })),
            })),
        };
        assert_eq!(chain.chain_depth(), 3);
        assert!(chain.validate_depth().is_ok());
    }

    #[test]
    fn test_actor_claim_chain_depth_exceeds_limit() {
        // Build a chain exceeding MAX_ACTOR_CHAIN_DEPTH
        let mut claim = ActorClaim {
            sub: "leaf".to_string(),
            nhi_type: None,
            act: None,
        };
        for i in 0..MAX_ACTOR_CHAIN_DEPTH {
            claim = ActorClaim {
                sub: format!("actor-{i}"),
                nhi_type: None,
                act: Some(Box::new(claim)),
            };
        }
        // depth is now MAX_ACTOR_CHAIN_DEPTH + 1
        assert!(claim.chain_depth() > MAX_ACTOR_CHAIN_DEPTH);
        assert!(claim.validate_depth().is_err());
    }

    #[test]
    fn test_delegation_chain_multi_hop() {
        let actor = ActorClaim {
            sub: "agent-top".to_string(),
            nhi_type: Some("agent".to_string()),
            act: Some(Box::new(ActorClaim {
                sub: "agent-mid".to_string(),
                nhi_type: Some("agent".to_string()),
                act: Some(Box::new(ActorClaim {
                    sub: "agent-leaf".to_string(),
                    nhi_type: None,
                    act: None,
                })),
            })),
        };

        let claims = JwtClaims::builder()
            .subject("user-123")
            .act(actor)
            .delegation_depth(3)
            .build();

        assert!(claims.is_delegated());
        let chain = claims.delegation_chain();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], "agent-top");
        assert_eq!(chain[1], "agent-mid");
        assert_eq!(chain[2], "agent-leaf");
    }
}
