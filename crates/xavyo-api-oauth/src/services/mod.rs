//! OAuth2/OIDC services.

pub mod authorization;
pub mod client;
pub mod device_code;
pub mod device_confirmation;
pub mod device_risk;
pub mod token;
pub mod userinfo;

pub use authorization::AuthorizationService;
pub use client::OAuth2ClientService;
pub use device_code::{
    DeviceAuthorizationResponse, DeviceAuthorizationStatus, DeviceCodeInfo, DeviceCodeService,
    DeviceTokenExchangeResult,
};
pub use device_confirmation::{
    ConfirmationCreated, ConfirmationValidationResult, DeviceConfirmationService,
};
pub use device_risk::{
    AdminNotifier, DeviceRiskService, LogOnlyAdminNotifier, RiskAction, RiskAssessment,
    RiskContext, RiskFactor, POINTS_BLACKLISTED_IP, POINTS_CODE_OLD, POINTS_FIRST_LOGIN,
    POINTS_NEW_COUNTRY, POINTS_USER_AGENT_MISMATCH, THRESHOLD_LOW_RISK, THRESHOLD_MEDIUM_RISK,
};
pub use token::TokenService;
pub use userinfo::UserInfoService;
