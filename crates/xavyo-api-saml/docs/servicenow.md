# ServiceNow SAML Integration Guide

This guide documents the specific SAML configuration requirements for integrating xavyo-idp with ServiceNow as a Service Provider.

## Overview

ServiceNow supports SAML 2.0 for federated single sign-on (SSO). When configuring xavyo-idp as an Identity Provider for ServiceNow, the following requirements must be met.

## SP Profile Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Entity ID | `https://<instance>.service-now.com` | Your ServiceNow instance URL |
| ACS URL | `https://<instance>.service-now.com/navpage.do` | Standard ACS endpoint |
| NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` | ServiceNow typically uses email |
| Sign Assertions | Yes | ServiceNow prefers signed assertions |
| Group Attribute | `Roles` | Used for role-based access |

## Required Attributes

### user_name (Required)

The `user_name` attribute maps to the ServiceNow user record's `user_name` field.

```xml
<saml:Attribute Name="user_name">
  <saml:AttributeValue>jsmith</saml:AttributeValue>
</saml:Attribute>
```

### user_email (Required)

The `user_email` attribute provides the user's email address.

```xml
<saml:Attribute Name="user_email">
  <saml:AttributeValue>jsmith@example.com</saml:AttributeValue>
</saml:Attribute>
```

### user_first_name and user_last_name (Recommended)

These attributes enable ServiceNow to display the user's full name.

```xml
<saml:Attribute Name="user_first_name">
  <saml:AttributeValue>John</saml:AttributeValue>
</saml:Attribute>
<saml:Attribute Name="user_last_name">
  <saml:AttributeValue>Smith</saml:AttributeValue>
</saml:Attribute>
```

### Roles (Multi-Value)

The `Roles` attribute supports multiple values for ServiceNow group/role assignment. Each role **must** be in a separate `<AttributeValue>` element.

```xml
<saml:Attribute Name="Roles">
  <saml:AttributeValue>itil</saml:AttributeValue>
  <saml:AttributeValue>admin</saml:AttributeValue>
  <saml:AttributeValue>approver_user</saml:AttributeValue>
</saml:Attribute>
```

> **Important**: Do NOT concatenate roles into a single value. ServiceNow expects each role in its own `<AttributeValue>` element.

## NameID Requirements

ServiceNow's NameID format is configurable via SP metadata. Common options:

- `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` (default)
- `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
- `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`

Example:
```xml
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  jsmith@example.com
</saml:NameID>
```

## SessionIndex Requirement

ServiceNow requires a `SessionIndex` attribute in the `<AuthnStatement>` for proper session management and Single Logout (SLO) support.

```xml
<saml:AuthnStatement
  AuthnInstant="2024-01-15T10:30:00Z"
  SessionIndex="_session_abc123">
  <saml:AuthnContext>
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </saml:AuthnContext>
</saml:AuthnStatement>
```

The `SessionIndex` value should be:
- Unique per session
- Stored for SLO correlation
- Returned in LogoutRequest if SLO is configured

## Signature Requirements

### Algorithm
- **Signature Method**: RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`)
- **Digest Method**: SHA-256 (`http://www.w3.org/2001/04/xmlenc#sha256`)
- **Canonicalization**: Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)

### What Must Be Signed
- The `<Assertion>` element should be signed
- ServiceNow validates signatures against the uploaded IdP certificate

## Audience Restriction

The `AudienceRestriction` must match ServiceNow's entity ID exactly:

```xml
<saml:AudienceRestriction>
  <saml:Audience>https://company.service-now.com</saml:Audience>
</saml:AudienceRestriction>
```

## Timing Requirements

| Condition | Requirement |
|-----------|-------------|
| `NotBefore` | Current time minus 2 minutes (clock skew tolerance) |
| `NotOnOrAfter` | Current time plus 5 minutes (300 seconds) |
| `IssueInstant` | Current UTC time |

ServiceNow has configurable clock skew tolerance (default: 5 minutes).

## Common Issues and Troubleshooting

### "User not found" Error
- Verify `user_name` attribute matches an existing ServiceNow user
- Check if auto-provisioning is enabled if users should be created

### "Signature validation failed"
- Verify the IdP certificate uploaded to ServiceNow is correct
- Ensure RSA-SHA256 is used (not SHA-1)
- Check certificate expiration

### Roles Not Applied
- Ensure each role is in a separate `<AttributeValue>` element
- Verify role names match ServiceNow role sys_ids or names exactly
- Check if "Update roles on each login" is enabled in ServiceNow

### Session Issues
- Verify `SessionIndex` is present in AuthnStatement
- Ensure SessionIndex is unique per session

## Example SAML Assertion

```xml
<saml:Assertion Version="2.0" ID="_assertion123" IssueInstant="2024-01-15T10:30:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      jsmith@example.com
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        NotOnOrAfter="2024-01-15T10:35:00Z"
        Recipient="https://company.service-now.com/navpage.do"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2024-01-15T10:28:00Z" NotOnOrAfter="2024-01-15T10:35:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://company.service-now.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="user_name">
      <saml:AttributeValue>jsmith</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="user_email">
      <saml:AttributeValue>jsmith@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="user_first_name">
      <saml:AttributeValue>John</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="user_last_name">
      <saml:AttributeValue>Smith</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="Roles">
      <saml:AttributeValue>itil</saml:AttributeValue>
      <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
  <saml:AuthnStatement AuthnInstant="2024-01-15T10:30:00Z" SessionIndex="_session_abc123">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
```

## References

- [ServiceNow SAML 2.0 Integration Documentation](https://docs.servicenow.com/bundle/sandiego-platform-security/page/integrate/single-sign-on/concept/c_IntegrateSAML2.0.html)
- [ServiceNow Multi-Provider SSO](https://docs.servicenow.com/bundle/sandiego-platform-security/page/integrate/single-sign-on/concept/c_MultipleIdentityProviders.html)
