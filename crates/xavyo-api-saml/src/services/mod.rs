//! Business logic services for SAML operations

pub mod assertion_builder;
pub mod group_service;
pub mod logout_parser;
pub mod metadata_generator;
pub mod request_parser;
pub mod signature_validator;
pub mod slo_builder;
pub mod slo_service;
pub mod sp_service;

pub use assertion_builder::{AssertionBuilder, SamlResponseOutput};
pub use group_service::GroupService;
pub use metadata_generator::MetadataGenerator;
pub use request_parser::RequestParser;
pub use signature_validator::SignatureValidator;
pub use slo_builder::SloBuilder;
pub use slo_service::SloService;
pub use sp_service::SpService;
