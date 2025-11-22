# Security Policy

## Reporting Security Vulnerabilities

The Freebird project takes security seriously. We appreciate your efforts to responsibly disclose your findings.

### Responsible Disclosure Process

**DO NOT** open public GitHub issues for security vulnerabilities.

Instead, please report security vulnerabilities by:

1. **Email**: Send details to security@freebird.dev (or project maintainer email)
2. **GitHub Security Advisories**: Use the "Security" tab on the GitHub repository
3. **GPG Encrypted**: For highly sensitive reports, use GPG encryption (key available on request)

### What to Include

Please provide:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and attack scenarios
- **Reproduction**: Step-by-step instructions to reproduce
- **PoC**: Proof-of-concept code if applicable
- **Severity**: Your assessment of severity (Critical/High/Medium/Low)
- **Environment**: Affected versions and configurations

### Response Timeline

- **Initial Response**: Within 48 hours
- **Triage**: Within 5 business days
- **Fix Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### Disclosure Policy

- We request **90 days** before public disclosure
- We will credit reporters (unless they prefer anonymity)
- We will coordinate disclosure timing with reporters

## Security Considerations

### Cryptographic Implementation

Freebird uses:
- **VOPRF**: P-256 curve with SHA-256
- **DLEQ Proofs**: For verifiable blind signatures
- **Constant-Time Operations**: To prevent timing attacks

### Known Limitations

- **Unaudited**: Freebird has not undergone formal security audit
- **Experimental**: Not recommended for production use without review
- **In-Memory Store**: Not recommended for high-security deployments (use Redis)

### Recommended Deployment

For production use:
1. ✅ Use Redis backend for nullifier storage
2. ✅ Enable HSM/KMS for key storage (when available)
3. ✅ Deploy behind TLS/HTTPS
4. ✅ Implement rate limiting
5. ✅ Monitor for anomalous token issuance patterns
6. ✅ Regular key rotation
7. ✅ Conduct security audit before production deployment

## Security Audit Status

**Last Audit**: None
**Status**: ⚠️ Unaudited

Professional security review is recommended before production use for sensitive applications.

## Security Updates

Security updates will be:
- Published in GitHub Security Advisories
- Tagged with security labels in releases
- Documented in CHANGELOG.md
- Announced via project communication channels

## Bug Bounty

We do not currently offer a bug bounty program. This may change as the project matures.

## Acknowledgments

We thank the security research community for helping make Freebird more secure.

## Contact

For security-related questions or concerns:
- Security Email: security@freebird.dev (setup required)
- Project Maintainers: See CONTRIBUTORS.md or GitHub

---

**Last Updated**: 2025-01-22
