//! JWT claims structure with standard and custom claims.
//!
//! Provides the `JwtClaims` struct containing both RFC 7519 standard claims
//! and Xavyo-specific custom claims (`tenant_id`, roles).

use crate::rar::AuthorizationDetail;
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

/// RFC 8693 §4.4 `may_act` claim — pre-authorization constraint.
///
/// When present in a subject token, restricts which actors can exchange
/// this token for a delegated token. The actor's `sub` must match one of
/// the allowed subjects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MayActClaim {
    /// Allowed actor subjects (NHI IDs that may act on behalf of the subject).
    pub sub: Vec<String>,
}

impl MayActClaim {
    /// Check if a given actor subject is allowed by this constraint.
    pub fn is_actor_allowed(&self, actor_sub: &str) -> bool {
        self.sub.is_empty() || self.sub.iter().any(|s| s == actor_sub)
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

    /// User email address (optional, included when email scope is granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// User display name (optional, included when profile scope is granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

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

    /// Pre-authorization constraint (RFC 8693 §4.4): which actors MAY act on
    /// behalf of this subject. If present, token exchange must verify the actor
    /// matches one of the `may_act` entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub may_act: Option<MayActClaim>,

    /// Confirmation claim (RFC 7800 / RFC 9449 §6). When present, this access
    /// token is sender-constrained (DPoP): `cnf.jkt` is the RFC 7638 thumbprint
    /// of the client's public key, and the token MUST be presented with a valid
    /// DPoP proof whose key thumbprint matches. Absent ⇒ ordinary bearer token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,

    /// Rich Authorization Requests (RFC 9396 §7): the granted
    /// `authorization_details` — fine-grained, structured permissions (e.g.
    /// `tool_access`) that resource servers enforce per element. Absent ⇒ the
    /// token carries only coarse `scope`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// OIDC Authentication Context Class Reference. xavyo uses `"1"`
    /// (single-factor) and `"2"` (multi-factor satisfied). Consumed by step-up
    /// authentication (RFC 9470). Absent on machine/partial tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,

    /// OIDC Authentication Methods References (RFC 8176): the methods used to
    /// authenticate, e.g. `["pwd"]`, `["pwd","otp","mfa"]`, `["mfa","hwk"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,

    /// OIDC `auth_time` — when the end-user authentication occurred (Unix
    /// seconds). NOT the token-issuance time; carried forward across refresh so
    /// `max_age` checks remain meaningful. Absent on machine/partial tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
}

/// RFC 7800 confirmation claim. Carries the proof-of-possession binding for a
/// sender-constrained token — at most one of: DPoP key thumbprint (`jkt`,
/// RFC 9449) or mTLS client-certificate thumbprint (`x5t#S256`, RFC 8705).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CnfClaim {
    /// RFC 7638 JWK SHA-256 thumbprint of the DPoP-binding public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    /// RFC 8705 §3.1 SHA-256 thumbprint of the client's mTLS certificate.
    #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
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

    /// Returns `true` if these claims represent a full access token.
    ///
    /// Purpose-bound tokens (e.g., partial MFA-verification tokens with
    /// `purpose = Some("mfa_verification")`) share the same signing key,
    /// issuer, and audience as access tokens, so any OAuth endpoint that
    /// accepts an access token MUST guard with `is_access_token()` to
    /// avoid trivial MFA / purpose bypass.
    #[must_use]
    pub fn is_access_token(&self) -> bool {
        self.purpose.is_none()
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
    pub fn effective_user_id(&self) -> Result<Uuid, String> {
        if self.is_acting_as() {
            self.acting_as_user_id
                .ok_or_else(|| "acting_as_user_id missing on delegated token".to_string())
        } else {
            self.sub
                .parse()
                .map_err(|e| format!("invalid sub claim: {e}"))
        }
    }

    /// Check if this is a delegated token (RFC 8693).
    #[must_use]
    pub fn is_delegated(&self) -> bool {
        self.act.is_some()
    }

    /// Returns the DPoP key thumbprint (`cnf.jkt`, RFC 9449) if this token is
    /// DPoP-bound, else `None`.
    #[must_use]
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.cnf.as_ref().and_then(|c| c.jkt.as_deref())
    }

    /// Returns the mTLS certificate thumbprint (`cnf["x5t#S256"]`, RFC 8705) if
    /// this token is certificate-bound, else `None`.
    #[must_use]
    pub fn cert_thumbprint(&self) -> Option<&str> {
        self.cnf.as_ref().and_then(|c| c.x5t_s256.as_deref())
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
    name: Option<String>,
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
    may_act: Option<MayActClaim>,
    cnf: Option<CnfClaim>,
    authorization_details: Option<Vec<AuthorizationDetail>>,
    acr: Option<String>,
    amr: Option<Vec<String>>,
    auth_time: Option<i64>,
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

    /// Set the user's display name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
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

    /// Set the `may_act` pre-authorization constraint (RFC 8693 §4.4).
    #[must_use]
    pub fn may_act(mut self, may_act: MayActClaim) -> Self {
        self.may_act = Some(may_act);
        self
    }

    /// Sender-constrain this token to a DPoP key (RFC 9449 §6): sets the
    /// `cnf.jkt` confirmation to the given RFC 7638 thumbprint.
    #[must_use]
    pub fn dpop_jkt(mut self, jkt: impl Into<String>) -> Self {
        let cnf = self.cnf.get_or_insert_with(CnfClaim::default);
        cnf.jkt = Some(jkt.into());
        self
    }

    /// Certificate-bind this token to an mTLS client cert (RFC 8705): sets the
    /// `cnf["x5t#S256"]` confirmation to the given certificate thumbprint.
    #[must_use]
    pub fn cert_thumbprint(mut self, x5t_s256: impl Into<String>) -> Self {
        let cnf = self.cnf.get_or_insert_with(CnfClaim::default);
        cnf.x5t_s256 = Some(x5t_s256.into());
        self
    }

    /// Set the granted RFC 9396 `authorization_details` (the token claim).
    #[must_use]
    pub fn authorization_details(mut self, details: Vec<AuthorizationDetail>) -> Self {
        self.authorization_details = Some(details);
        self
    }

    /// Set the OIDC `acr` (authentication context class reference).
    #[must_use]
    pub fn acr(mut self, acr: impl Into<String>) -> Self {
        self.acr = Some(acr.into());
        self
    }

    /// Set the OIDC `amr` (authentication methods references, RFC 8176).
    #[must_use]
    pub fn amr(mut self, amr: Vec<String>) -> Self {
        self.amr = Some(amr);
        self
    }

    /// Set the OIDC `auth_time` (when end-user authentication occurred, seconds).
    #[must_use]
    pub fn auth_time(mut self, auth_time: i64) -> Self {
        self.auth_time = Some(auth_time);
        self
    }

    /// Build the JWT claims.
    ///
    /// # Defaults
    ///
    /// - `sub`: Empty string if not set — `encode_token` / jwt_auth reject that
    /// - `iss`: "xavyo" if not set
    /// - `aud`: Empty vec if not set
    /// - `exp`: 1 hour from now if not set
    /// - `iat`: Current time if not set
    /// - `jti`: New UUID v4 if not set
    ///
    /// # Security
    ///
    /// C-4: If a JTI was explicitly set to an empty string, it is replaced with a
    /// new UUID v4. Empty JTIs would bypass revocation checks in jwt_auth middleware.
    #[must_use]
    pub fn build(self) -> JwtClaims {
        let now = Utc::now().timestamp();

        // C-4: Guard against empty JTI — required for revocation tracking
        let jti = match self.jti {
            Some(ref j) if !j.is_empty() => j.clone(),
            _ => Uuid::new_v4().to_string(),
        };

        JwtClaims {
            sub: required_jwt_subject(self.sub).unwrap_or_default(),
            iss: self.iss.unwrap_or_else(|| "xavyo".to_string()),
            aud: self.aud,
            exp: self.exp.unwrap_or(now + 3600), // Default: 1 hour
            iat: self.iat.unwrap_or(now),
            jti,
            tid: self.tid,
            roles: self.roles,
            purpose: self.purpose,
            email: self.email,
            name: self.name,
            scope: self.scope,
            acting_as_poa_id: self.acting_as_poa_id,
            acting_as_user_id: self.acting_as_user_id,
            acting_as_session_id: self.acting_as_session_id,
            act: self.act,
            delegation_id: self.delegation_id,
            delegation_depth: self.delegation_depth,
            may_act: self.may_act,
            cnf: self.cnf,
            authorization_details: self.authorization_details,
            acr: self.acr,
            amr: self.amr,
            auth_time: self.auth_time,
        }
    }
}

/// Empty subjects must not be minted; they would hash into a fake service account.
pub fn required_jwt_subject(sub: Option<String>) -> Option<String> {
    sub.filter(|s| !s.is_empty())
}

/// True when `sub` can be used as a JWT subject at a trust boundary.
#[must_use]
pub fn jwt_subject_is_usable(sub: &str) -> bool {
    !sub.is_empty()
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
    fn empty_jwt_subject_is_not_usable() {
        assert!(required_jwt_subject(None).is_none());
        assert!(required_jwt_subject(Some(String::new())).is_none());
        assert_eq!(
            required_jwt_subject(Some("user-123".into())).as_deref(),
            Some("user-123")
        );
        assert!(!jwt_subject_is_usable(""));
        assert!(jwt_subject_is_usable("user-123"));
        assert!(JwtClaims::builder().build().sub.is_empty());
    }

    #[test]
    fn test_empty_jti_replaced_with_uuid() {
        // C-4: Explicitly setting an empty JTI should be replaced with a UUID
        let claims = JwtClaims::builder().subject("user-123").jwt_id("").build();

        assert!(
            !claims.jti.is_empty(),
            "Empty JTI should be replaced with UUID"
        );
        // Should be a valid UUID
        assert!(Uuid::parse_str(&claims.jti).is_ok());
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

    /// Regression guard for the CRITICAL MFA-bypass fix (deep review §2.1).
    /// A token with NO `purpose` is a full access token; any purpose-bound
    /// token (e.g. the partial MFA-verification token) is NOT. OAuth endpoints
    /// that accept access tokens MUST reject the latter via `is_access_token()`.
    #[test]
    fn test_is_access_token_discriminates_purpose() {
        // Full access token: no purpose claim.
        let access = JwtClaims::builder().subject("user-123").build();
        assert!(
            access.is_access_token(),
            "a token without a purpose must be treated as an access token"
        );

        // Partial MFA-verification token: purpose = mfa_verification.
        let partial = JwtClaims::builder()
            .subject("user-123")
            .purpose("mfa_verification")
            .build();
        assert!(
            !partial.is_access_token(),
            "an mfa_verification token must NOT be accepted as an access token"
        );

        // Any other purpose-bound token is likewise rejected.
        let other = JwtClaims::builder()
            .subject("user-123")
            .purpose("password_reset")
            .build();
        assert!(!other.is_access_token());
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
        assert_eq!(claims.effective_user_id().unwrap(), donor_id);
    }

    #[test]
    fn test_claims_not_acting_as() {
        let user_id = Uuid::new_v4();
        let claims = JwtClaims::builder().subject(user_id.to_string()).build();

        assert!(!claims.is_acting_as());
        assert_eq!(claims.actual_actor_id(), &user_id.to_string());
        assert_eq!(claims.effective_user_id().unwrap(), user_id);
    }

    #[test]
    fn effective_user_id_does_not_drop_invalid_sub() {
        let claims = JwtClaims::builder().subject("not-a-uuid").build();
        assert!(claims.effective_user_id().is_err());
        let src = include_str!("claims.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("self.sub.parse().ok()"),
            "invalid JWT sub must not silently become None"
        );
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
        assert!(!json.contains("may_act"));
    }

    #[test]
    fn test_may_act_claim_allows_listed_actor() {
        let may_act = MayActClaim {
            sub: vec!["agent-001".into(), "agent-002".into()],
        };
        assert!(may_act.is_actor_allowed("agent-001"));
        assert!(may_act.is_actor_allowed("agent-002"));
        assert!(!may_act.is_actor_allowed("agent-003"));
    }

    #[test]
    fn test_may_act_claim_empty_allows_all() {
        let may_act = MayActClaim { sub: vec![] };
        assert!(may_act.is_actor_allowed("any-agent"));
    }

    #[test]
    fn test_may_act_claim_serialization() {
        let claims = JwtClaims::builder()
            .subject("user-123")
            .may_act(MayActClaim {
                sub: vec!["agent-001".into()],
            })
            .build();

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("may_act"));
        assert!(json.contains("agent-001"));

        let parsed: JwtClaims = serde_json::from_str(&json).unwrap();
        assert!(parsed.may_act.is_some());
        assert!(parsed.may_act.unwrap().is_actor_allowed("agent-001"));
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

    #[test]
    fn builder_sets_authentication_context() {
        let claims = JwtClaims::builder()
            .subject("u1")
            .acr("2")
            .amr(vec![
                "pwd".to_string(),
                "otp".to_string(),
                "mfa".to_string(),
            ])
            .auth_time(1_700_000_000)
            .build();
        assert_eq!(claims.acr.as_deref(), Some("2"));
        assert_eq!(
            claims.amr,
            Some(vec!["pwd".into(), "otp".into(), "mfa".into()])
        );
        assert_eq!(claims.auth_time, Some(1_700_000_000));
    }

    #[test]
    fn auth_context_claims_absent_by_default() {
        let claims = JwtClaims::builder().subject("u1").build();
        assert!(claims.acr.is_none());
        assert!(claims.amr.is_none());
        assert!(claims.auth_time.is_none());
    }

    #[test]
    fn auth_context_serde_round_trip_and_legacy_compat() {
        // Round-trip with the claims present.
        let claims = JwtClaims::builder()
            .subject("u1")
            .acr("1")
            .amr(vec!["pwd".to_string()])
            .auth_time(42)
            .build();
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"acr\":\"1\""));
        assert!(json.contains("\"auth_time\":42"));
        let back: JwtClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back.acr.as_deref(), Some("1"));
        assert_eq!(back.amr, Some(vec!["pwd".into()]));
        assert_eq!(back.auth_time, Some(42));

        // Legacy token (no acr/amr/auth_time) deserializes with the fields None —
        // so tokens issued before this change keep working.
        let legacy = r#"{"sub":"u1","iss":"xavyo","aud":[],"exp":9999999999,"iat":1,"jti":"j"}"#;
        let parsed: JwtClaims = serde_json::from_str(legacy).unwrap();
        assert!(parsed.acr.is_none());
        assert!(parsed.amr.is_none());
        assert!(parsed.auth_time.is_none());
    }
}
