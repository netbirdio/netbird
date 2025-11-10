# Security Package

This package provides comprehensive security utilities for the NetBird project, including password hashing, input validation, rate limiting, and audit logging.

## Overview

The security package is designed to provide secure, efficient, and well-documented security utilities that can be used throughout the NetBird application. All components are designed with security best practices in mind and include proper error handling and resource management.

## Components

### 1. Password Hashing (`password.go`)

Provides secure password hashing and validation using Argon2id, which is the recommended password hashing algorithm.

**Features:**
- Argon2id password hashing (memory-hard, resistant to GPU/ASIC attacks)
- Constant-time password verification (prevents timing attacks)
- Password policy enforcement
- Random password generation
- Common password detection

**Example Usage:**
```go
// Hash a password
hash, err := security.HashPassword("mySecurePassword", nil)
if err != nil {
    return err
}

// Verify a password
valid, err := security.VerifyPassword("mySecurePassword", hash)
if err != nil {
    return err
}

// Validate password meets policy
policy := security.DefaultPasswordPolicy()
err := security.ValidatePassword("myPassword", policy)
if err != nil {
    return err // Password doesn't meet requirements
}

// Generate a random password
password, err := security.GenerateRandomPassword(16, policy)
```

**Security Considerations:**
- Uses `crypto/rand` for secure random number generation
- Constant-time comparison prevents timing attacks
- Argon2id provides resistance against GPU and ASIC attacks
- Passwords are never logged or exposed

### 2. Input Validation (`validation.go`)

Provides comprehensive input validation and sanitization to prevent security vulnerabilities like XSS, SQL injection, and command injection.

**Features:**
- Struct validation with tags
- HTTP request validation
- JSON validation
- File upload validation
- TLS configuration validation
- Certificate validation
- Input sanitization (XSS protection)
- URL sanitization (open redirect protection)

**Example Usage:**
```go
// Create validator
validator := security.NewValidator()

// Validate struct
type User struct {
    Email string `validate:"required,email"`
    Age   int    `validate:"min=18,max=120"`
}

user := User{Email: "user@example.com", Age: 25}
err := validator.ValidateStruct(&user)

// Validate HTTP request
rules := map[string]string{
    "email": "required|email",
    "age":   "required|min:18|max:120",
}
err := validator.ValidateRequest(r, rules)

// Sanitize input
safeInput := validator.SanitizeInput(userInput)
```

**Security Considerations:**
- Pre-compiled regular expressions for efficiency
- Comprehensive XSS protection
- Open redirect prevention
- File upload validation prevents malicious files
- TLS configuration validation ensures secure connections

### 3. Rate Limiting (`ratelimit.go`)

Provides IP-based and user-based rate limiting to prevent abuse and DoS attacks.

**Features:**
- Token bucket rate limiting
- IP-based and user-based limiting
- Automatic cleanup of old entries
- Memory leak prevention (max size limits)
- LRU-style eviction
- HTTP middleware support
- Rate limit headers

**Example Usage:**
```go
// Create rate limiter
limiter := security.NewRateLimiter(
    100,              // 100 requests per window
    time.Minute,      // 1 minute window
    5*time.Minute,    // 5 minute ban duration
)

// Use as HTTP middleware
router.Use(limiter.Middleware)

// Check rate limit manually
allowed := limiter.Allow(clientIP, userID)
if !allowed {
    return errors.New("rate limit exceeded")
}

// Get rate limit headers
headers := limiter.GetRateLimitHeaders(clientIP, userID)
for k, v := range headers {
    w.Header().Set(k, v[0])
}

// Clean up when done
defer limiter.Close()
```

**Security Considerations:**
- IP validation prevents spoofing
- Max size limits prevent memory exhaustion
- Automatic cleanup prevents memory leaks
- Thread-safe for concurrent use
- LRU eviction ensures fair resource usage

### 4. Audit Logging (`audit.go`)

Provides secure audit logging for security-relevant events with automatic sensitive data redaction.

**Features:**
- Buffered logging for performance
- Automatic background flushing
- Sensitive data redaction (passwords, tokens, etc.)
- Thread-safe operations
- File and/or stderr output
- Request logging
- Security event logging
- User activity logging
- Data access logging

**Example Usage:**
```go
// Create audit logger
logger, err := security.NewAuditLogger("/var/log/audit.log")
if err != nil {
    return err
}
defer logger.Close()

// Log an event
event := &security.AuditEvent{
    Action:  "user_login",
    Subject: "user123",
    Object:  "account",
    Status:  "success",
    IP:      "192.168.1.1",
}
logger.Log(event)

// Log HTTP request
logger.LogRequest(r, http.StatusOK, nil, nil)

// Log security event
logger.LogSecurityEvent("login_attempt", "user123", "success", r, nil)

// Log user activity
logger.LogUserActivity("user123", "profile_update", "success", r, nil)

// Log data access
logger.LogDataAccess("user123", "read", "user", "user456", "success", r)
```

**Security Considerations:**
- Automatic redaction of passwords, tokens, and API keys
- Buffered logging for performance
- Thread-safe for concurrent use
- Proper resource cleanup
- JSON formatting for easy parsing

## Security Best Practices

### Password Security
- Always use `HashPassword` to hash passwords before storage
- Never store plaintext passwords
- Use `VerifyPassword` for password verification (constant-time)
- Enforce password policies using `ValidatePassword`
- Use `GenerateRandomPassword` for generating secure passwords

### Input Validation
- Always validate user input before processing
- Use `SanitizeInput` for user-generated content displayed in HTML
- Use `SanitizeURL` to prevent open redirect attacks
- Validate file uploads using `ValidateFile`
- Validate TLS configurations using `ValidateTLSConfig`

### Rate Limiting
- Use rate limiting on all public endpoints
- Configure appropriate limits based on your use case
- Monitor rate limit violations for potential attacks
- Use IP validation to prevent spoofing
- Call `Close()` when done to prevent resource leaks

### Audit Logging
- Log all security-relevant events
- Use appropriate log levels
- Ensure sensitive data is redacted
- Monitor audit logs for suspicious activity
- Call `Close()` when done to flush remaining events

## Thread Safety

All components in this package are designed to be thread-safe:
- `RateLimiter`: All methods are safe for concurrent use
- `Validator`: Safe for concurrent use after initialization
- `AuditLogger`: All methods are safe for concurrent use
- Password functions: Stateless, safe for concurrent use

## Resource Management

All components properly manage resources:
- `RateLimiter`: Call `Close()` to stop cleanup goroutine
- `AuditLogger`: Call `Close()` to flush events and close file
- Automatic cleanup of old entries prevents memory leaks
- Proper defer statements ensure cleanup on errors

## Error Handling

All functions return errors instead of panicking:
- Password functions return errors for invalid input
- Validation functions return descriptive errors
- Rate limiter handles errors gracefully
- Audit logger logs errors but continues operation

## Performance Considerations

- Pre-compiled regular expressions for efficient validation
- Buffered logging for better performance
- Automatic cleanup prevents unbounded memory growth
- LRU eviction ensures fair resource usage
- Efficient data structures and algorithms

## Testing

All components should be thoroughly tested:
- Unit tests for individual functions
- Integration tests for component interactions
- Security tests for vulnerability detection
- Performance tests for resource usage

## Contributing

When contributing to this package:
1. Follow security best practices
2. Add comprehensive documentation
3. Include error handling
4. Ensure thread safety
5. Add appropriate tests
6. Consider resource management
7. Think about edge cases

## License

This package is part of the NetBird project and follows the same license terms.

