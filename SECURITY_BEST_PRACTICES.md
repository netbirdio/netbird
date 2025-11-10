# NetBird Security Best Practices

## Overview

This document outlines the security measures implemented in the NetBird project and provides guidance for maintaining security standards.

## Security Principles

### 1. Defense in Depth

- Multiple layers of security controls
- Fail-safe defaults
- Least privilege principle
- Complete mediation

### 2. Secure by Default

- All security features enabled by default
- Secure configurations out of the box
- Minimal attack surface

### 3. Fail Securely

- Errors don't expose sensitive information
- Failures default to secure state
- Graceful degradation

## Security Measures Implemented

### Input Validation and Sanitization

#### Request Body Size Limits

- **JSON Requests**: Maximum 10MB
- **File Uploads**: Maximum 100MB
- **Audit Logging**: Maximum 1MB

**Implementation**: All request bodies are read through `io.LimitReader` to prevent DoS attacks.

#### Path Traversal Protection

- Rejects paths containing `..`
- Validates resolved paths are within base directory
- Logs path traversal attempts
- Uses absolute path validation

**Example**:

```go
// Validate path is within base directory
absFilePath, _ := filepath.Abs(file)
absBaseDir, _ := filepath.Abs(baseDir)
if !strings.HasPrefix(absFilePath, absBaseDir) {
    return errors.New("path traversal attempt")
}
```

#### Input Sanitization

- XSS protection in `SanitizeInput`
- URL sanitization
- Command injection prevention
- SQL injection prevention

### Error Handling

#### Error Message Sanitization

Error messages are sanitized to prevent information leakage:

- **Removed**: File paths, stack traces, database details
- **Limited**: Message length (200 characters max)
- **Logged**: Full error details server-side only

**Implementation**:

```go
func sanitizeErrorMessage(errMsg string) string {
    // Remove file paths
    pathRegex := regexp.MustCompile(`(/[^\s]+|\\[^\s]+|C:\\[^\s]+)`)
    errMsg = pathRegex.ReplaceAllString(errMsg, "[path]")

    // Remove stack traces
    stackRegex := regexp.MustCompile(`(?m)^\s+at\s+.*$|goroutine\s+\d+|panic:|runtime\.`)
    errMsg = stackRegex.ReplaceAllString(errMsg, "")

    // Limit length
    if len(errMsg) > 200 {
        errMsg = errMsg[:200] + "..."
    }

    return strings.TrimSpace(errMsg)
}
```

### File Permissions

#### Secure Default Permissions

- **Temporary Files**: 0600 (owner read/write only)
- **Log Files**: 0640 (owner read/write, group read)
- **Directories**: 0750 (owner rwx, group rx)
- **Unix Sockets**: 0660 (owner/group read/write)
- **Debug Bundles**: 0600 (owner read/write only)
- **Config Files**: 0640 (owner read/write, group read)

**Rationale**: Prevents unauthorized access to sensitive data while allowing necessary group access.

### Resource Management

#### Goroutine Management

- All goroutines have proper cleanup
- Context-based cancellation
- WaitGroup synchronization
- Defer statements for cleanup

#### File Handle Management

- All file handles closed with defer
- Temporary files cleaned up
- Error handling for close operations

#### Network Connection Management

- Connections closed properly
- Timeouts on all network operations
- Context cancellation support

### Memory Management

#### Bounded Data Structures

- Maps have maximum size limits
- LRU eviction for rate limiters
- FIFO eviction for memory stores
- Capacity limits on slices

**Example**:

```go
const maxEvents = 10000

if len(m.events) >= maxEvents {
    // Remove oldest event
    for id := range m.events {
        delete(m.events, id)
        break
    }
}
```

### Cryptographic Security

#### Password Hashing

- **Algorithm**: Argon2id
- **Salt**: Cryptographically secure random (16 bytes)
- **Parameters**: Configurable memory, time, threads
- **Verification**: Constant-time comparison

#### Encryption

- **New Code**: AES-GCM with random nonces
- **Legacy Code**: AES-CBC (documented as insecure, for backward compatibility only)

**Warning**: Legacy encryption uses hardcoded IV and should not be used for new code.

### HTTP Security Headers

#### Security Headers Implemented

- `X-Content-Type-Options: nosniff` - Prevents MIME type sniffing
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-XSS-Protection: 1; mode=block` - XSS protection
- `Referrer-Policy: strict-origin-when-cross-origin` - Referrer control
- `Permissions-Policy` - Feature policy

#### HSTS (HTTP Strict Transport Security)

- Enabled for HTTPS connections
- Max age: 2 years (configurable)
- Include subdomains: Yes
- Preload: Configurable

### Rate Limiting

#### Features

- IP-based rate limiting
- Per-user rate limiting
- Automatic cleanup of old entries
- Banned IP/user tracking
- LRU eviction for memory management

#### Configuration

- Maximum requests per window
- Window duration
- Ban duration
- Maximum entries (prevents memory leaks)

### Authentication and Authorization

#### JWT Validation

- Algorithm whitelist (RS256, RS384, RS512, ES256, ES384, ES512)
- Expiration required
- Issuer validation
- Audience validation
- Key rotation support
- Cache control headers

#### IP Validation

- Validates IP addresses from headers
- Prevents IP spoofing
- Uses `net.ParseIP()` for validation

### Audit Logging

#### Features

- Buffered logging for performance
- Automatic background flushing
- Sensitive data redaction
- Thread-safe operations
- File and/or stderr output

#### Redacted Data

- Passwords
- Tokens
- API keys
- Authorization headers
- Cookies

## Security Checklist

### Before Deployment

- [ ] All security headers configured
- [ ] File permissions verified
- [ ] Input validation enabled
- [ ] Rate limiting configured
- [ ] Error messages sanitized
- [ ] Resource limits set
- [ ] Audit logging enabled
- [ ] TLS/SSL configured
- [ ] Secrets management configured
- [ ] Security updates applied

### Code Review Checklist

- [ ] Input validation on all user inputs
- [ ] Error messages don't leak information
- [ ] File permissions are secure
- [ ] Resources are properly cleaned up
- [ ] Memory limits are enforced
- [ ] Cryptographic operations use secure algorithms
- [ ] No hardcoded secrets
- [ ] SQL injection prevention
- [ ] XSS prevention
- [ ] Path traversal prevention

## Common Vulnerabilities and Mitigations

### SQL Injection

**Mitigation**: Parameterized queries, input validation, database name sanitization

### XSS (Cross-Site Scripting)

**Mitigation**: Input sanitization, output encoding, CSP headers

### Path Traversal

**Mitigation**: Path validation, absolute path checking, base directory validation

### Command Injection

**Mitigation**: Input validation, whitelist approach, regex validation

### DoS (Denial of Service)

**Mitigation**: Request size limits, rate limiting, resource limits, timeouts

### Information Disclosure

**Mitigation**: Error message sanitization, security headers, access controls

### Memory Leaks

**Mitigation**: Bounded data structures, proper cleanup, resource limits

## Security Monitoring

### Logging

- All security events logged
- Failed authentication attempts
- Rate limit violations
- Path traversal attempts
- Error conditions

### Metrics

- Request rates
- Error rates
- Resource usage
- Authentication failures

## Incident Response

### Security Incident Procedure

1. Identify and contain the incident
2. Assess the impact
3. Remediate vulnerabilities
4. Document the incident
5. Review and improve

### Reporting Security Issues

- Report to: security@netbird.io
- Include: Description, steps to reproduce, impact assessment
- Response time: Within 48 hours

## Compliance

### Standards Compliance

- OWASP Top 10
- CWE Top 25
- Security best practices
- Industry standards

## Updates and Maintenance

### Security Updates

- Regular dependency updates
- Security patch management
- Vulnerability scanning
- Penetration testing

### Security Reviews

- Quarterly security audits
- Code review for security
- Architecture reviews
- Threat modeling

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Go Security Best Practices](https://go.dev/doc/security/best-practices)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Contact

For security concerns or questions:

- Email: security@netbird.io
- Security Policy: See SECURITY.md

---

**Last Updated**: November 10, 2025
