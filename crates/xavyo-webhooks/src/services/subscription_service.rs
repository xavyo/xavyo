//! Webhook subscription CRUD service.
//!
//! Provides business logic for creating, listing, updating, and deleting
//! webhook subscriptions with URL validation, SSRF protection, secret
//! encryption, subscription limits, and event type validation.

use sqlx::PgPool;
use uuid::Uuid;

use crate::crypto;
use crate::error::WebhookError;
use crate::models::{
    CreateWebhookSubscriptionRequest, ListSubscriptionsQuery, UpdateWebhookSubscriptionRequest,
    WebhookSubscriptionListResponse, WebhookSubscriptionResponse,
};
use crate::validation;
use xavyo_db::models::{CreateWebhookSubscription, UpdateWebhookSubscription, WebhookSubscription};

/// Default maximum active subscriptions per tenant.
pub const DEFAULT_MAX_SUBSCRIPTIONS: i64 = 25;

/// Service for webhook subscription operations.
#[derive(Clone)]
pub struct SubscriptionService {
    pool: PgPool,
    encryption_key: Vec<u8>,
    max_subscriptions: i64,
    allow_http: bool,
}

impl SubscriptionService {
    /// Create a new subscription service.
    #[must_use] 
    pub fn new(pool: PgPool, encryption_key: Vec<u8>) -> Self {
        Self {
            pool,
            encryption_key,
            max_subscriptions: DEFAULT_MAX_SUBSCRIPTIONS,
            allow_http: false,
        }
    }

    /// Set the maximum subscriptions per tenant.
    #[must_use] 
    pub fn with_max_subscriptions(mut self, max: i64) -> Self {
        self.max_subscriptions = max;
        self
    }

    /// Allow HTTP URLs (for development/testing).
    #[must_use] 
    pub fn with_allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Create a new webhook subscription.
    pub async fn create_subscription(
        &self,
        tenant_id: Uuid,
        created_by: Option<Uuid>,
        request: CreateWebhookSubscriptionRequest,
    ) -> Result<WebhookSubscriptionResponse, WebhookError> {
        // Validate URL and SSRF
        validation::validate_webhook_url(&request.url, self.allow_http)?;

        // Validate event types
        validation::validate_event_types(&request.event_types)?;

        // Check subscription limit
        let count = WebhookSubscription::count_by_tenant(&self.pool, tenant_id, None).await?;
        if count >= self.max_subscriptions {
            return Err(WebhookError::SubscriptionLimitExceeded {
                limit: self.max_subscriptions,
            });
        }

        // Encrypt secret if provided
        let secret_encrypted = match &request.secret {
            Some(secret) if !secret.is_empty() => {
                Some(crypto::encrypt_secret(secret, &self.encryption_key)?)
            }
            _ => None,
        };

        let input = CreateWebhookSubscription {
            tenant_id,
            name: request.name,
            description: request.description,
            url: request.url,
            secret_encrypted,
            event_types: request.event_types,
            created_by,
        };

        let sub = WebhookSubscription::create(&self.pool, input).await?;
        Ok(subscription_to_response(sub))
    }

    /// List webhook subscriptions for a tenant with pagination.
    pub async fn list_subscriptions(
        &self,
        tenant_id: Uuid,
        query: ListSubscriptionsQuery,
    ) -> Result<WebhookSubscriptionListResponse, WebhookError> {
        let limit = query.limit.clamp(1, 100);
        let offset = query.offset.max(0);

        let subs = WebhookSubscription::list_by_tenant(
            &self.pool,
            tenant_id,
            limit,
            offset,
            query.enabled,
        )
        .await?;

        let total =
            WebhookSubscription::count_by_tenant(&self.pool, tenant_id, query.enabled).await?;

        Ok(WebhookSubscriptionListResponse {
            items: subs.into_iter().map(subscription_to_response).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a single webhook subscription.
    pub async fn get_subscription(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<WebhookSubscriptionResponse, WebhookError> {
        let sub = WebhookSubscription::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(WebhookError::SubscriptionNotFound)?;

        Ok(subscription_to_response(sub))
    }

    /// Update a webhook subscription.
    pub async fn update_subscription(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        request: UpdateWebhookSubscriptionRequest,
    ) -> Result<WebhookSubscriptionResponse, WebhookError> {
        // Validate URL if provided
        if let Some(ref url) = request.url {
            validation::validate_webhook_url(url, self.allow_http)?;
        }

        // Validate event types if provided
        if let Some(ref event_types) = request.event_types {
            validation::validate_event_types(event_types)?;
        }

        // Encrypt new secret if provided
        let secret_encrypted = match &request.secret {
            Some(secret) if !secret.is_empty() => {
                Some(crypto::encrypt_secret(secret, &self.encryption_key)?)
            }
            _ => None,
        };

        // If re-enabling, reset consecutive failures
        let re_enabling = request.enabled == Some(true);

        let input = UpdateWebhookSubscription {
            name: request.name,
            description: request.description,
            url: request.url,
            secret_encrypted,
            event_types: request.event_types,
            enabled: request.enabled,
        };

        let sub = WebhookSubscription::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(WebhookError::SubscriptionNotFound)?;

        // Reset consecutive failures if re-enabling
        if re_enabling {
            WebhookSubscription::reset_consecutive_failures(&self.pool, tenant_id, id).await?;
        }

        // Re-fetch to get latest state (with reset failures)
        if re_enabling {
            let refreshed = WebhookSubscription::find_by_id(&self.pool, tenant_id, id)
                .await?
                .ok_or(WebhookError::SubscriptionNotFound)?;
            Ok(subscription_to_response(refreshed))
        } else {
            Ok(subscription_to_response(sub))
        }
    }

    /// Delete a webhook subscription.
    pub async fn delete_subscription(&self, tenant_id: Uuid, id: Uuid) -> Result<(), WebhookError> {
        let deleted = WebhookSubscription::delete(&self.pool, tenant_id, id).await?;
        if !deleted {
            return Err(WebhookError::SubscriptionNotFound);
        }
        Ok(())
    }
}

/// Convert a DB model to an API response.
fn subscription_to_response(sub: WebhookSubscription) -> WebhookSubscriptionResponse {
    WebhookSubscriptionResponse {
        id: sub.id,
        tenant_id: sub.tenant_id,
        name: sub.name,
        description: sub.description,
        url: sub.url,
        event_types: sub.event_types,
        enabled: sub.enabled,
        consecutive_failures: sub.consecutive_failures,
        created_at: sub.created_at,
        updated_at: sub.updated_at,
    }
}
