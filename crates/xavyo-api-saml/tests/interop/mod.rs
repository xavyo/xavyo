//! SAML Service Provider Interoperability Tests
//!
//! This module contains tests to verify SAML assertion compatibility with major
//! Service Providers (Salesforce, ServiceNow, Workday, AWS SSO).
//!
//! These tests validate:
//! - Assertion structure compliance
//! - Attribute formatting per SP requirements
//! - NameID format handling
//! - Signature algorithm compatibility
//! - Multi-value attribute handling

pub mod common;

pub mod salesforce_tests;
pub mod servicenow_tests;
pub mod workday_tests;
pub mod aws_sso_tests;
