/// Errors that can occur during ext_authz processing.
#[derive(Debug, thiserror::Error)]
pub enum ExtAuthzError {
    #[error("missing request attributes")]
    MissingAttributes,

    #[error("missing HTTP request in attributes")]
    MissingHttpRequest,

    #[error("JWT extraction failed: {0}")]
    JwtExtraction(String),

    #[error("invalid subject ID: {0}")]
    InvalidSubjectId(String),

    #[error("invalid tenant ID: {0}")]
    InvalidTenantId(String),

    #[error("NHI identity not found: {0}")]
    NhiNotFound(uuid::Uuid),

    #[error("NHI identity not usable (state: {0})")]
    NhiNotUsable(String),

    #[error("risk score {score} exceeds threshold {threshold}")]
    RiskScoreExceeded { score: i32, threshold: i32 },

    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl ExtAuthzError {
    /// Returns the appropriate HTTP status code for this error.
    pub fn status_code(&self) -> u32 {
        match self {
            Self::MissingAttributes | Self::MissingHttpRequest | Self::JwtExtraction(_) => 400,
            Self::InvalidSubjectId(_) | Self::InvalidTenantId(_) | Self::NhiNotFound(_) => 401,
            Self::NhiNotUsable(_)
            | Self::RiskScoreExceeded { .. }
            | Self::AuthorizationDenied(_) => 403,
            Self::Database(_) | Self::Internal(_) => 500,
        }
    }

    /// Returns a sanitized message safe to return to clients.
    ///
    /// Unlike `Display` (which includes operational details for logging),
    /// this omits UUIDs, risk scores, lifecycle states, and policy reasons
    /// to prevent information leakage.
    pub fn client_message(&self) -> &'static str {
        match self {
            Self::MissingAttributes | Self::MissingHttpRequest => "invalid request",
            Self::JwtExtraction(_) | Self::InvalidSubjectId(_) | Self::InvalidTenantId(_) => {
                "authentication required"
            }
            Self::NhiNotFound(_) => "identity not found",
            Self::NhiNotUsable(_)
            | Self::RiskScoreExceeded { .. }
            | Self::AuthorizationDenied(_) => "access denied",
            Self::Database(_) | Self::Internal(_) => "internal error",
        }
    }

    /// Returns a machine-readable error code.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::MissingAttributes => "missing_attributes",
            Self::MissingHttpRequest => "missing_http_request",
            Self::JwtExtraction(_) => "jwt_extraction_failed",
            Self::InvalidSubjectId(_) => "invalid_subject_id",
            Self::InvalidTenantId(_) => "invalid_tenant_id",
            Self::NhiNotFound(_) => "nhi_not_found",
            Self::NhiNotUsable(_) => "nhi_not_usable",
            Self::RiskScoreExceeded { .. } => "risk_score_exceeded",
            Self::AuthorizationDenied(_) => "authorization_denied",
            Self::Database(_) => "database_error",
            Self::Internal(_) => "internal_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(ExtAuthzError::MissingAttributes.status_code(), 400);
        assert_eq!(ExtAuthzError::MissingHttpRequest.status_code(), 400);
        assert_eq!(
            ExtAuthzError::JwtExtraction("test".into()).status_code(),
            400
        );
        assert_eq!(
            ExtAuthzError::InvalidSubjectId("test".into()).status_code(),
            401
        );
        assert_eq!(
            ExtAuthzError::InvalidTenantId("test".into()).status_code(),
            401
        );
        assert_eq!(
            ExtAuthzError::NhiNotFound(uuid::Uuid::new_v4()).status_code(),
            401
        );
        assert_eq!(
            ExtAuthzError::NhiNotUsable("suspended".into()).status_code(),
            403
        );
        assert_eq!(
            ExtAuthzError::RiskScoreExceeded {
                score: 80,
                threshold: 75
            }
            .status_code(),
            403
        );
        assert_eq!(
            ExtAuthzError::AuthorizationDenied("denied".into()).status_code(),
            403
        );
        assert_eq!(ExtAuthzError::Internal("oops".into()).status_code(), 500);
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            ExtAuthzError::MissingAttributes.error_code(),
            "missing_attributes"
        );
        assert_eq!(
            ExtAuthzError::MissingHttpRequest.error_code(),
            "missing_http_request"
        );
        assert_eq!(
            ExtAuthzError::JwtExtraction("test".into()).error_code(),
            "jwt_extraction_failed"
        );
        assert_eq!(
            ExtAuthzError::InvalidSubjectId("test".into()).error_code(),
            "invalid_subject_id"
        );
        assert_eq!(
            ExtAuthzError::InvalidTenantId("test".into()).error_code(),
            "invalid_tenant_id"
        );
        assert_eq!(
            ExtAuthzError::NhiNotFound(uuid::Uuid::new_v4()).error_code(),
            "nhi_not_found"
        );
        assert_eq!(
            ExtAuthzError::NhiNotUsable("suspended".into()).error_code(),
            "nhi_not_usable"
        );
        assert_eq!(
            ExtAuthzError::RiskScoreExceeded {
                score: 80,
                threshold: 75
            }
            .error_code(),
            "risk_score_exceeded"
        );
        assert_eq!(
            ExtAuthzError::AuthorizationDenied("denied".into()).error_code(),
            "authorization_denied"
        );
        assert_eq!(
            ExtAuthzError::Internal("oops".into()).error_code(),
            "internal_error"
        );
    }

    #[test]
    fn test_error_display() {
        let err = ExtAuthzError::RiskScoreExceeded {
            score: 80,
            threshold: 75,
        };
        assert_eq!(err.to_string(), "risk score 80 exceeds threshold 75");

        let err = ExtAuthzError::NhiNotUsable("suspended".into());
        assert_eq!(
            err.to_string(),
            "NHI identity not usable (state: suspended)"
        );

        let err = ExtAuthzError::AuthorizationDenied("no matching policy".into());
        assert_eq!(err.to_string(), "authorization denied: no matching policy");
    }

    #[test]
    fn test_client_messages_are_sanitized() {
        // Verify client messages don't leak operational details
        let err = ExtAuthzError::NhiNotFound(uuid::Uuid::new_v4());
        assert_eq!(err.client_message(), "identity not found");
        // Display has the UUID, client_message does not
        assert!(err.to_string().contains('-')); // UUID has dashes
        assert!(!err.client_message().contains('-'));

        let err = ExtAuthzError::NhiNotUsable("suspended".into());
        assert_eq!(err.client_message(), "access denied");
        assert!(!err.client_message().contains("suspended"));

        let err = ExtAuthzError::RiskScoreExceeded {
            score: 80,
            threshold: 75,
        };
        assert_eq!(err.client_message(), "access denied");
        assert!(!err.client_message().contains("80"));

        let err = ExtAuthzError::AuthorizationDenied("no matching policy".into());
        assert_eq!(err.client_message(), "access denied");
        assert!(!err.client_message().contains("policy"));

        let err = ExtAuthzError::JwtExtraction("token expired".into());
        assert_eq!(err.client_message(), "authentication required");
        assert!(!err.client_message().contains("expired"));

        let err = ExtAuthzError::Database(sqlx::Error::RowNotFound);
        assert_eq!(err.client_message(), "internal error");
    }

    #[test]
    fn test_database_error_from() {
        // Verify that sqlx::Error converts to ExtAuthzError::Database
        let sqlx_err = sqlx::Error::RowNotFound;
        let err: ExtAuthzError = sqlx_err.into();
        assert_eq!(err.status_code(), 500);
        assert_eq!(err.error_code(), "database_error");
    }
}
