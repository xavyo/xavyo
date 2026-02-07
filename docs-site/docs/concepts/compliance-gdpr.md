---
title: Compliance & GDPR
description: GDPR compliance features in xavyo -- data protection classification, right to erasure, audit trails, consent management, and data portability.
sidebar_position: 7
---

# Compliance and GDPR

The General Data Protection Regulation (GDPR) sets the global standard for data protection and privacy. While GDPR is a European regulation, its influence extends globally -- most multinational organizations apply GDPR-level protections across their operations. xavyo provides built-in capabilities to support GDPR compliance within the identity and access management domain.

This page covers how xavyo addresses specific GDPR requirements, the data protection classification system, audit trail capabilities, and integration with broader compliance programs.

## GDPR and Identity Management

GDPR intersects with identity management at several points. xavyo handles personal data (names, email addresses, authentication credentials, access history) and must process that data in accordance with GDPR principles:

| GDPR Principle | Identity Management Implication | xavyo Capability |
|---|---|---|
| **Lawfulness, fairness, transparency** | Users must know what identity data is collected and why | Audit trail, GDPR reports |
| **Purpose limitation** | Identity data must be used only for documented purposes | Data protection classification, entitlement documentation |
| **Data minimization** | Collect only necessary identity data | Configurable user attributes, no unnecessary data collection |
| **Accuracy** | Identity data must be kept current | Self-service profile management, lifecycle synchronization |
| **Storage limitation** | Identity data should not be retained longer than necessary | Lifecycle management, archival, scheduled deletion |
| **Integrity and confidentiality** | Identity data must be protected against unauthorized access | Multi-tenant RLS, encryption at rest, credential rotation |
| **Accountability** | Organizations must demonstrate compliance | Comprehensive audit trail, GDPR reporting |

## Data Subject Rights

GDPR grants individuals specific rights regarding their personal data. xavyo supports the following rights through its API:

### Right of Access (Article 15)

Data subjects have the right to receive a copy of their personal data. xavyo provides a GDPR report endpoint that generates a comprehensive summary:

```bash
curl -s -X POST "$API/governance/gdpr/report" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT" \
  -d '{"user_id": "subject-user-id"}'
```

The GDPR report includes:
- **Personal data** -- name, email, profile attributes
- **Authentication history** -- login events, MFA registrations, devices
- **Access rights** -- current entitlement assignments, role memberships, group memberships
- **Governance history** -- access requests, certification decisions, lifecycle events
- **Sessions** -- active and historical session data

This report satisfies the Data Subject Access Request (DSAR) requirement by providing a complete view of the personal data held within the identity platform.

### Right to Rectification (Article 16)

Data subjects have the right to correct inaccurate personal data. xavyo supports this through:

- **Self-service profile management** -- users can update their own name, contact information, and custom attributes through the `/me` API
- **Admin user management** -- administrators can correct user data through the user management API
- **Email change workflows** -- email address changes require verification of the new address

### Right to Erasure (Article 17)

Data subjects have the right to request deletion of their personal data ("right to be forgotten"). In the identity management context, this means:

1. **Deactivate the user account** -- prevent any further authentication or access
2. **Remove personal data** -- replace identifiable attributes with anonymized values
3. **Retain governance records** -- audit trail entries must be retained for compliance but can be anonymized (replacing personal identifiers with hashed or pseudonymized values)

The lifecycle management system handles erasure through the deactivation and archival states. When a user moves to the archived state, their personal data can be scrubbed while retaining the structural audit trail.

### Right to Data Portability (Article 20)

Data subjects have the right to receive their personal data in a structured, machine-readable format. xavyo's GDPR report endpoint returns data in JSON format, which satisfies the portability requirement.

### Right to Restriction of Processing (Article 18)

Data subjects can request that processing of their data be restricted. In xavyo, this maps to the **suspended** lifecycle state -- the account exists but cannot authenticate or be used for processing.

## Data Protection Classification

xavyo supports data protection classification at the application and entitlement level, enabling organizations to track which systems process personal data and at what sensitivity level:

### Classification Levels

| Level | Description | Example |
|---|---|---|
| **None** | No personal data processed | Internal documentation system |
| **Personal** | Standard personal data (Article 6) | Employee directory, email system |
| **Sensitive** | Sensitive personal data (Article 9) | HR system with health records |
| **Special Category** | Special categories of data | Biometric authentication, health data, political opinions |

Classifications are assigned when registering applications:

```bash
curl -s -X POST "$API/governance/applications" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT" \
  -d '{
    "name": "HR System",
    "app_type": "internal",
    "description": "Human resources management",
    "data_protection_classification": "sensitive"
  }'
```

### Classification Impact

Data protection classification affects governance rigor:
- **Sensitive and special category** applications require higher approval levels for access requests
- Entitlements in classified applications receive higher risk weights in risk scoring
- Certification campaigns for classified applications receive increased scrutiny
- Access to classified applications is highlighted in GDPR reports

## Audit Trail

xavyo maintains a comprehensive, immutable audit trail that satisfies GDPR's accountability principle. Every significant action is recorded:

### What is Audited

- **Authentication events** -- login, logout, MFA challenge, password change, account lockout
- **Administrative actions** -- user creation, role assignment, policy changes, tenant configuration
- **Governance decisions** -- certification decisions, access request approvals/denials, SoD exemption grants
- **Provisioning operations** -- account creation in target systems, entitlement assignment, credential rotation
- **Data access** -- GDPR report generation, user data export

### Audit Record Structure

Each audit record captures:
- **Timestamp** -- when the action occurred (UTC)
- **Actor** -- who performed the action (user ID, or system for automated actions)
- **Action** -- what was done (created, updated, deleted, approved, denied)
- **Resource** -- what was affected (user, role, entitlement, policy)
- **Tenant** -- which tenant the action belongs to
- **Details** -- action-specific context (before/after values, justification)

### Audit Retention

Audit records are retained within xavyo according to tenant configuration. For long-term retention, audit logs can be exported to external SIEM systems:

```bash
# Configure a SIEM destination
curl -s -X POST "$API/governance/siem/destinations" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT" \
  -d '{
    "name": "Splunk Production",
    "destination_type": "splunk",
    "config": {
      "url": "https://splunk.corp.example.com:8088",
      "token": "splunk-hec-token"
    }
  }'
```

Supported SIEM destinations:
- **Splunk** -- HTTP Event Collector (HEC)
- **Syslog** -- RFC 5424 formatted syslog messages
- **Webhook** -- custom HTTP endpoint with configurable payload format

### Dead Letter Queue

When SIEM delivery fails (network issues, destination downtime), events are stored in a dead letter queue for later redelivery:

```bash
# View failed SIEM deliveries
curl -s "$API/governance/siem/destinations/$DEST_ID/dead-letter" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT"

# Redeliver failed events
curl -s -X POST "$API/governance/siem/destinations/$DEST_ID/dead-letter/redeliver" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT"
```

## Breach Notification Support

GDPR Article 33 requires notification of data breaches to supervisory authorities within 72 hours. While breach detection and notification is outside the scope of an identity platform, xavyo supports the process through:

- **Security alerts** -- anomalous authentication patterns, unusual access patterns, and potential account compromise trigger alerts
- **Session audit** -- rapid identification of which sessions were active during a breach window
- **Access snapshots** -- point-in-time records of who had access to what systems at the time of the breach
- **GDPR reports** -- rapid generation of data subject impact assessments

## Consent and Lawful Basis

GDPR requires that organizations document the lawful basis for processing personal data. In the identity management context:

- **Contract** (Article 6(1)(b)) -- processing is necessary for employment or service contracts
- **Legal obligation** (Article 6(1)(c)) -- processing is required by law (e.g., financial regulatory identity verification)
- **Legitimate interest** (Article 6(1)(f)) -- processing is necessary for security purposes (authentication, access control)

xavyo's entitlement model supports purpose documentation -- each entitlement can include a description of why the access is needed, and access requests require business justification. This creates an auditable record linking access grants to business purposes.

## Per-Tenant GDPR Compliance

Because xavyo is multi-tenant, GDPR compliance operates at the tenant level:

- Each tenant's GDPR report covers only that tenant's data
- Data protection classifications are scoped to tenant applications
- Audit trails are tenant-isolated -- a DSAR response from Tenant A cannot contain Tenant B's data
- Tenant deletion removes all personal data for that tenant

This aligns with GDPR's data controller/processor model -- each tenant is a data controller for their users, and xavyo acts as a data processor.

## Compliance Reporting

xavyo provides governance reports that support compliance programs:

```bash
# Generate a compliance report
curl -s -X POST "$API/governance/reports/generate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT" \
  -d '{
    "report_type": "compliance",
    "parameters": {
      "period": "2026-Q1"
    }
  }'
```

Reports can cover:
- Access certification completion rates
- SoD violation and remediation statistics
- Lifecycle event summaries (joiners, movers, leavers)
- Orphan account detection results
- NHI certification status

Reports can be scheduled for automatic generation:

```bash
curl -s -X POST "$API/governance/reports/schedules" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT" \
  -d '{
    "name": "Monthly Compliance Report",
    "report_template_id": "template-id",
    "schedule": "monthly",
    "recipients": ["compliance@example.com"]
  }'
```

## Related Concepts

- **[Identity Governance](./identity-governance.md)** -- the governance framework that supports GDPR compliance
- **[Multi-Tenancy](./multi-tenancy.md)** -- tenant-level data isolation and DSAR scoping
- **[Lifecycle Management](./lifecycle-management.md)** -- supporting right to erasure through lifecycle states
- **[Zero Trust Architecture](./zero-trust.md)** -- protecting personal data through continuous verification
