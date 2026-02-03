# Salesforce SAML Integration Guide

This guide documents the specific SAML configuration requirements for integrating xavyo-idp with Salesforce as a Service Provider.

## Overview

Salesforce supports SAML 2.0 for federated single sign-on (SSO). When configuring xavyo-idp as an Identity Provider for Salesforce, the following requirements must be met.

## SP Profile Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Entity ID | `https://saml.salesforce.com` | Salesforce's standard entity ID |
| ACS URL | `https://login.salesforce.com?so=<org_id>` | Replace `<org_id>` with your Salesforce organization ID |
| NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` | Salesforce requires email-based NameID |
| Sign Assertions | Yes | Salesforce requires signed assertions |
| Assertion Validity | 300 seconds (5 minutes) | Maximum validity window |

## Required Attributes

### FederationIdentifier (Required)

The `FederationIdentifier` attribute is **required** for Salesforce SSO and maps to the user's unique identifier in Salesforce.

```xml
<saml:Attribute Name="FederationIdentifier">
  <saml:AttributeValue>user@example.com</saml:AttributeValue>
</saml:Attribute>
```

### User.Email (Required)

The `User.Email` attribute provides the user's email address.

```xml
<saml:Attribute Name="User.Email">
  <saml:AttributeValue>user@example.com</saml:AttributeValue>
</saml:Attribute>
```

## NameID Requirements

- **Format**: Must be `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- **Value**: The user's email address
- **Uniqueness**: Must uniquely identify the user across all federated sessions

Example:
```xml
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  user@example.com
</saml:NameID>
```

## Signature Requirements

### Algorithm
- **Signature Method**: RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`)
- **Digest Method**: SHA-256 (`http://www.w3.org/2001/04/xmlenc#sha256`)
- **Canonicalization**: Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)

> **Note**: SHA-1 signatures are deprecated and may be rejected by Salesforce.

### What Must Be Signed
- The `<Assertion>` element **must** be signed
- The `<Response>` element may optionally be signed

## Audience Restriction

The `AudienceRestriction` must match Salesforce's entity ID exactly:

```xml
<saml:AudienceRestriction>
  <saml:Audience>https://saml.salesforce.com</saml:Audience>
</saml:AudienceRestriction>
```

## RelayState Preservation

When Salesforce initiates SSO (SP-initiated flow), it may include a `RelayState` parameter. This value **must** be:
1. Preserved during the authentication flow
2. Returned in the SAML Response
3. Used by Salesforce to redirect the user to the intended destination

## Timing Requirements

| Condition | Requirement |
|-----------|-------------|
| `NotBefore` | Current time minus 2 minutes (clock skew tolerance) |
| `NotOnOrAfter` | Current time plus 5 minutes (300 seconds) |
| `IssueInstant` | Current UTC time |

Salesforce validates these timestamps strictly. Ensure NTP synchronization between your IdP and Salesforce.

## Common Issues and Troubleshooting

### "Invalid signature" Error
- Verify the certificate uploaded to Salesforce matches your IdP's signing certificate
- Ensure using RSA-SHA256, not SHA-1
- Check that Exclusive C14N is used for canonicalization

### "Subject NameID is missing or invalid"
- Verify NameID format is `emailAddress`
- Ensure the email matches a user in Salesforce

### "Assertion is not valid yet or has expired"
- Synchronize server clocks using NTP
- Verify `NotBefore` allows for clock skew
- Check assertion validity doesn't exceed 5 minutes

### "Federation ID not found"
- Ensure `FederationIdentifier` attribute is included
- Verify the value matches the user's Federation ID in Salesforce

## Example SAML Assertion

```xml
<saml:Assertion Version="2.0" ID="_assertion123" IssueInstant="2024-01-15T10:30:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      user@example.com
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        NotOnOrAfter="2024-01-15T10:35:00Z"
        Recipient="https://login.salesforce.com?so=00Dxx000000xxxx"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2024-01-15T10:28:00Z" NotOnOrAfter="2024-01-15T10:35:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://saml.salesforce.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="FederationIdentifier">
      <saml:AttributeValue>user@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="User.Email">
      <saml:AttributeValue>user@example.com</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
  <saml:AuthnStatement AuthnInstant="2024-01-15T10:30:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
```

## References

- [Salesforce SAML Identity Provider Documentation](https://help.salesforce.com/s/articleView?id=sf.sso_saml.htm)
- [SAML 2.0 Technical Overview](https://www.oasis-open.org/committees/download.php/27819/sstc-saml-tech-overview-2.0-cd-02.pdf)
