# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in xavyo, please report it privately:

**Email:** pascal@heartbit.ai

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

## Response Timeline

| Severity | Initial Response | Fix Target |
|----------|------------------|------------|
| Critical | 24 hours | 48 hours |
| High | 48 hours | 1 week |
| Medium | 1 week | 2 weeks |
| Low | 2 weeks | Next release |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | Yes |

## Security Best Practices

When deploying xavyo:

1. **Use TLS** — Always run behind HTTPS in production
2. **Rotate JWT keys** — Rotate signing keys periodically
3. **Secure PostgreSQL** — Use strong passwords, enable SSL, restrict network access
4. **Environment variables** — Never commit `.env` files; use secrets management
5. **Keep updated** — Apply security patches promptly

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Contributors will be credited in release notes (unless they prefer anonymity).
