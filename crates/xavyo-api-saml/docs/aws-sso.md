# AWS SSO (IAM Identity Center) SAML Integration Guide

This guide documents the specific SAML configuration requirements for integrating xavyo-idp with AWS IAM Identity Center (formerly AWS SSO) as a Service Provider.

## Overview

AWS IAM Identity Center supports SAML 2.0 for federated access to AWS accounts and applications. AWS has specific requirements for SAML assertions that enable role-based access to AWS resources.

## SP Profile Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Entity ID | `urn:amazon:webservices` | Fixed AWS value |
| ACS URL | `https://signin.aws.amazon.com/saml` | Standard AWS SAML endpoint |
| NameID Format | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` | AWS requires persistent NameID |
| Sign Assertions | Yes | AWS requires signed assertions |

## Required Attributes

### Role Attribute (Required)

The `Role` attribute is **critical** for AWS SSO and uses a specific namespace and format.

**Attribute Namespace**: `https://aws.amazon.com/SAML/Attributes/Role`

**Value Format**: Each role is a comma-separated pair of `role_arn,provider_arn`:

```xml
<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
  <saml:AttributeValue>arn:aws:iam::123456789012:role/Admin,arn:aws:iam::123456789012:saml-provider/MyIdP</saml:AttributeValue>
</saml:Attribute>
```

### Multi-Role Support

When a user has access to multiple AWS roles, each role **must** be in a separate `<AttributeValue>` element:

```xml
<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
  <saml:AttributeValue>arn:aws:iam::123456789012:role/Admin,arn:aws:iam::123456789012:saml-provider/MyIdP</saml:AttributeValue>
  <saml:AttributeValue>arn:aws:iam::123456789012:role/Developer,arn:aws:iam::123456789012:saml-provider/MyIdP</saml:AttributeValue>
  <saml:AttributeValue>arn:aws:iam::987654321098:role/CrossAccountRole,arn:aws:iam::987654321098:saml-provider/MyIdP</saml:AttributeValue>
</saml:Attribute>
```

> **IMPORTANT**: Do NOT combine multiple roles into a single AttributeValue. Each role pair must be its own AttributeValue element.

### Role ARN Format

Each role value must follow this exact format:
```
arn:aws:iam::<account-id>:role/<role-name>,arn:aws:iam::<account-id>:saml-provider/<provider-name>
```

Components:
- **Role ARN**: `arn:aws:iam::<account-id>:role/<role-name>`
- **Provider ARN**: `arn:aws:iam::<account-id>:saml-provider/<provider-name>`
- **Separator**: Single comma (`,`) with no spaces

### RoleSessionName Attribute (Required)

The `RoleSessionName` attribute is **required** and becomes the principal name in CloudTrail logs.

**Attribute Namespace**: `https://aws.amazon.com/SAML/Attributes/RoleSessionName`

```xml
<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
  <saml:AttributeValue>jsmith@example.com</saml:AttributeValue>
</saml:Attribute>
```

**Requirements**:
- Maximum 64 characters
- Must match regex: `[\w+=,.@-]*`
- Typically the username or email
- Used for CloudTrail audit logging

### SessionDuration Attribute (Optional but Recommended)

The `SessionDuration` attribute specifies how long the AWS session is valid.

**Attribute Namespace**: `https://aws.amazon.com/SAML/Attributes/SessionDuration`

```xml
<saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
  <saml:AttributeValue>3600</saml:AttributeValue>
</saml:Attribute>
```

**Value Requirements**:
- Minimum: 900 seconds (15 minutes)
- Maximum: 43200 seconds (12 hours)
- Must be a string representation of an integer
- If omitted, AWS uses the role's default duration

## NameID Requirements

AWS requires persistent NameID format for consistent user identification:

```xml
<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
  user-unique-identifier-uuid
</saml:NameID>
```

Key points:
- Format **must** be `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
- Value should be unique and immutable (UUID recommended)
- Used for session correlation in AWS

## Audience Restriction

The `AudienceRestriction` **must** be `urn:amazon:webservices`:

```xml
<saml:AudienceRestriction>
  <saml:Audience>urn:amazon:webservices</saml:Audience>
</saml:AudienceRestriction>
```

> **Note**: This is a URN, not a URL. Do not use `https://`.

## Signature Requirements

### Algorithm
- **Signature Method**: RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`)
- **Digest Method**: SHA-256 (`http://www.w3.org/2001/04/xmlenc#sha256`)

> **Note**: SHA-1 is deprecated by AWS. Always use SHA-256.

### What Must Be Signed
- The `<Assertion>` element **must** be signed
- The `<Response>` may optionally be signed

## Common Issues and Troubleshooting

### "RoleSessionName is required"
- Ensure the `RoleSessionName` attribute is present
- Verify the namespace is exactly `https://aws.amazon.com/SAML/Attributes/RoleSessionName`

### "Access denied" or No Roles Available
- Verify Role attribute namespace is exactly `https://aws.amazon.com/SAML/Attributes/Role`
- Check role ARN format: `arn:aws:iam::<account>:role/<name>,arn:aws:iam::<account>:saml-provider/<provider>`
- Ensure no spaces around the comma in the ARN pair
- Verify the SAML provider exists in the AWS account
- Check IAM role trust policy allows the SAML provider

### "SessionDuration must be between 900 and 43200"
- Ensure duration value is between 900 and 43200
- Verify the value is a string (not XML number)

### "Invalid audience"
- Ensure audience is exactly `urn:amazon:webservices`
- Do not use URL format

### "Signature validation failed"
- Verify IdP certificate is uploaded to AWS IAM Identity Provider
- Ensure RSA-SHA256 is used
- Check certificate hasn't expired

### Multi-Account Role Issues
- Each account's roles need their own SAML provider
- Provider ARN must match the account where the role exists

## Example SAML Assertion

```xml
<saml:Assertion Version="2.0" ID="_assertion123" IssueInstant="2024-01-15T10:30:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
      550e8400-e29b-41d4-a716-446655440000
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        NotOnOrAfter="2024-01-15T10:35:00Z"
        Recipient="https://signin.aws.amazon.com/saml"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2024-01-15T10:28:00Z" NotOnOrAfter="2024-01-15T10:35:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>urn:amazon:webservices</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
      <saml:AttributeValue>arn:aws:iam::123456789012:role/Admin,arn:aws:iam::123456789012:saml-provider/MyIdP</saml:AttributeValue>
      <saml:AttributeValue>arn:aws:iam::123456789012:role/Developer,arn:aws:iam::123456789012:saml-provider/MyIdP</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
      <saml:AttributeValue>jsmith</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
      <saml:AttributeValue>3600</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
  <saml:AuthnStatement AuthnInstant="2024-01-15T10:30:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>
```

## AWS-Specific Quirks

1. **URN vs URL for Audience** - Use `urn:amazon:webservices`, not a URL
2. **Multi-role format** - Each role must be separate AttributeValue, not concatenated
3. **Role ARN pair** - Both role ARN and provider ARN required, comma-separated
4. **Persistent NameID** - Must use persistent format for consistent user tracking
5. **SessionDuration limits** - Strictly enforced 900-43200 second range
6. **RoleSessionName in CloudTrail** - Choose carefully, it appears in all audit logs

## AWS CLI Usage After SSO

After SAML authentication, users can use the AWS CLI with assumed role credentials:

```bash
# Using AWS SSO CLI
aws sso login --profile my-sso-profile

# Or with SAML response file
aws sts assume-role-with-saml \
  --role-arn arn:aws:iam::123456789012:role/Admin \
  --principal-arn arn:aws:iam::123456789012:saml-provider/MyIdP \
  --saml-assertion file://saml-response.txt
```

## References

- [AWS IAM Identity Center Documentation](https://docs.aws.amazon.com/singlesignon/)
- [Configuring SAML Assertions for AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html)
- [AWS SAML Attribute Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html#saml_role-session-attribute)
