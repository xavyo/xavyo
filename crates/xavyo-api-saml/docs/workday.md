# Workday SAML Integration Guide

This guide documents the specific SAML configuration requirements for integrating xavyo-idp with Workday as a Service Provider.

## Overview

Workday supports SAML 2.0 for federated single sign-on (SSO). Workday has strict requirements for SAML assertions that differ from other Service Providers. This guide covers those specific requirements.

## SP Profile Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Entity ID | `http://www.workday.com/<tenant>` | Your Workday tenant identifier |
| ACS URL | `https://www.myworkday.com/<tenant>/login-saml.flex` | Tenant-specific ACS endpoint |
| NameID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | Workday uses unspecified format |
| Sign Assertions | **Yes - REQUIRED** | Unsigned assertions are REJECTED |
| Assertion Validity | 300 seconds (5 minutes) | Strict enforcement |

## Critical Requirements

### Signature is MANDATORY

> **IMPORTANT**: Workday **WILL REJECT** unsigned assertions. This is non-negotiable.

Every SAML assertion sent to Workday **must** include a valid XML signature. Unsigned assertions will result in authentication failure with no detailed error message.

## Required Attributes

### WorkdayID (Required)

The `WorkdayID` attribute is **required** and must match the user's Workday ID (typically the employee ID).

```xml
<saml:Attribute Name="WorkdayID">
  <saml:AttributeValue>EMP-12345</saml:AttributeValue>
</saml:Attribute>
```

> **Note**: The WorkdayID typically maps to the employee ID in Workday HCM.

## NameID Requirements

Workday uses the `unspecified` NameID format. The value should be the employee's identifier (typically employee ID).

```xml
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
  EMP-12345
</saml:NameID>
```

Key points:
- Format **must** be `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
- Value should be the employee ID (not email)
- Value must match the WorkdayID attribute value

## Signature Requirements

### Algorithm (CRITICAL)
- **Signature Method**: RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`) **REQUIRED**
- **Digest Method**: SHA-256 (`http://www.w3.org/2001/04/xmlenc#sha256`) **REQUIRED**
- **Canonicalization**: Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`) **REQUIRED**

> **WARNING**: SHA-1 signatures are deprecated and may be rejected. Always use RSA-SHA256.

### What Must Be Signed
- The `<Assertion>` element **MUST** be signed
- Unsigned assertions are rejected immediately

### Certificate Requirements
- Certificate must be uploaded to Workday's SSO configuration
- Certificate should have at least 2048-bit RSA key
- Certificate must not be expired

## Timing Requirements (Strict Enforcement)

Workday enforces timing conditions strictly:

| Condition | Requirement |
|-----------|-------------|
| `NotBefore` | Current time minus 2 minutes (120 seconds) |
| `NotOnOrAfter` | Current time plus 5 minutes (300 seconds max) |
| `IssueInstant` | Current UTC time |

### Clock Skew Tolerance

Workday allows approximately 5 minutes (300 seconds) of clock skew tolerance. However:
- **NotBefore** should be set to 2 minutes in the past to account for minor clock differences
- **NotOnOrAfter** should not exceed 5 minutes from issue time
- Total assertion validity window should not exceed 7 minutes (2 min buffer + 5 min validity)

> **Recommendation**: Synchronize your IdP server with NTP to ensure accurate timestamps.

## Audience Restriction

The `AudienceRestriction` must match Workday's entity ID exactly:

```xml
<saml:AudienceRestriction>
  <saml:Audience>http://www.workday.com/company-tenant</saml:Audience>
</saml:AudienceRestriction>
```

## Common Issues and Troubleshooting

### "Assertion signature validation failed"
- Verify the signing certificate uploaded to Workday matches your IdP
- Ensure RSA-SHA256 is used (not SHA-1)
- Verify Exclusive C14N canonicalization
- Check that the assertion (not just response) is signed

### "Assertion has expired" / "Assertion not yet valid"
- Check server time synchronization (use NTP)
- Verify NotBefore is set slightly in the past (2 minutes)
- Verify NotOnOrAfter is within 5 minutes of issue time

### "User not found"
- Verify WorkdayID attribute is present
- Ensure WorkdayID value matches the employee ID in Workday
- Check NameID value matches WorkdayID

### "Invalid NameID format"
- Ensure format is `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
- Do not use emailAddress format for Workday

### Generic "SSO failed" Error
- Check all of the above
- Workday often returns generic errors for security reasons
- Enable SAML debugging in Workday if available

## Example SAML Assertion

```xml
<saml:Assertion Version="2.0" ID="_assertion123" IssueInstant="2024-01-15T10:30:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
  </ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">
      EMP-12345
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        NotOnOrAfter="2024-01-15T10:35:00Z"
        Recipient="https://www.myworkday.com/company/login-saml.flex"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2024-01-15T10:28:00Z" NotOnOrAfter="2024-01-15T10:35:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>http://www.workday.com/company</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="WorkdayID">
      <saml:AttributeValue>EMP-12345</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
  <saml:AuthnStatement AuthnInstant="2024-01-15T10:30:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
```

## Workday-Specific Quirks

1. **Unsigned assertions are silently rejected** - Always sign assertions
2. **Employee ID is primary identifier** - Not email, unlike most SPs
3. **Strict timing validation** - Clock sync is critical
4. **Generic error messages** - Workday rarely gives detailed error info
5. **No RelayState support** - Workday doesn't use RelayState for deep linking

## References

- [Workday Community - Configure SAML SSO](https://community.workday.com/)
- [Workday Integration Security Guide](https://doc.workday.com/admin-guide/en-us/integration-security/)
