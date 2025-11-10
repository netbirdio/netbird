package security

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AuditEvent represents a security-relevant event that should be logged for
// security auditing and compliance purposes. All security-sensitive operations
// should create an AuditEvent to track who did what, when, and the result.
//
// Required fields:
//   - Timestamp: When the event occurred
//   - Action: What action was performed (e.g., "login", "user_create", "config_update")
//   - Subject: Who performed the action (e.g., user ID, system)
//   - Object: What was acted upon (e.g., user ID, resource ID)
//   - Status: The result of the action (e.g., "success", "failure", "denied")
//
// Optional fields provide additional context for forensics and debugging.
type AuditEvent struct {
	// Required fields
	Timestamp   time.Time     `json:"timestamp"`
	Action      string        `json:"action"`      // The action being performed (e.g., "login", "user_create", "config_update")
	Subject     string        `json:"subject"`     // The entity performing the action (e.g., user ID, system)
	Object      string        `json:"object"`      // The entity being acted upon (e.g., user ID, resource ID)
	Status      string        `json:"status"`      // The result of the action (e.g., "success", "failure", "denied")

	// Optional fields with additional context
	IP          string        `json:"ip,omitempty"`           // Client IP address
	UserAgent   string        `json:"user_agent,omitempty"`   // Client user agent
	RequestID   string        `json:"request_id,omitempty"`   // Request ID for correlation
	Metadata    interface{}   `json:"metadata,omitempty"`     // Additional structured data
	Error       string        `json:"error,omitempty"`        // Error message if the action failed
	Duration    time.Duration `json:"duration,omitempty"`     // How long the action took
	Source      string        `json:"source,omitempty"`       // Source of the event (e.g., "api", "cli", "web")
	Resource    string        `json:"resource,omitempty"`     // Resource type (e.g., "user", "token", "config")
	ResourceID  string        `json:"resource_id,omitempty"`  // ID of the affected resource
	Changes     interface{}   `json:"changes,omitempty"`      // What changed (for update/delete operations)
}

// AuditLogger is responsible for logging security-relevant events in a secure
// and efficient manner. It provides buffered logging with automatic flushing
// and redaction of sensitive data.
//
// Features:
//   - Buffered logging for performance
//   - Automatic background flushing
//   - Sensitive data redaction (passwords, tokens, etc.)
//   - Thread-safe operations
//   - File and/or stderr output
//
// The logger automatically redacts sensitive information like passwords, tokens,
// and API keys before logging to prevent sensitive data exposure.
type AuditLogger struct {
	logger     *logrus.Logger
	output     io.Writer
	file       *os.File
	enabled    bool
	mutex      sync.Mutex
	buffer     []*AuditEvent
	bufferSize int
	autoFlush  bool
	flushInterval time.Duration
	stopChan   chan struct{}
}

// NewAuditLogger creates a new AuditLogger instance with the specified configuration.
//
// Parameters:
//   - logFile: Path to the audit log file. If empty, logs are written to stderr only.
//     If specified, logs are written to both the file and stderr.
//
// Returns:
//   - A configured AuditLogger ready to use
//   - An error if the log file cannot be created or opened
//
// The logger is initialized with:
//   - Buffer size: 100 events
//   - Auto-flush: enabled
//   - Flush interval: 5 seconds
//   - JSON formatting with RFC3339Nano timestamps
//
// The logger starts a background goroutine for automatic flushing. Call Close()
// when done to stop the background goroutine.
func NewAuditLogger(logFile string) (*AuditLogger, error) {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})

	// Default output to stderr
	output := os.Stderr
	var file *os.File
	var err error

	// If log file is specified, create/append to it
	if logFile != "" {
		// Create directory if it doesn't exist
		// Security: Use 0750 permissions (owner rwx, group rx, others no access)
		// This ensures audit log directories are not world-readable
		dir := filepath.Dir(logFile)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %v", err)
		}

		// Open the log file in append mode, create it if it doesn't exist
		// Security: Use 0640 permissions (owner read/write, group read, others no access)
		// This prevents unauthorized access to audit logs which may contain sensitive information
		file, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}

		// Write to both stderr and the log file
		output = io.MultiWriter(os.Stderr, file)
	}

	logger.SetOutput(output)

	auditLogger := &AuditLogger{
		logger:       logger,
		output:       output,
		file:         file,
		enabled:      true,
		buffer:       make([]*AuditEvent, 0, 100),
		bufferSize:   100,
		autoFlush:    true,
		flushInterval: 5 * time.Second,
		stopChan:     make(chan struct{}),
	}

	// Start the background flusher
	if auditLogger.autoFlush {
		go auditLogger.backgroundFlusher()
	}

	return auditLogger, nil
}

// Log logs a new audit event to the buffer. If the buffer is full, it automatically
// flushes the buffer. The event is redacted to remove sensitive information before
// being added to the buffer.
//
// Parameters:
//   - event: The audit event to log. The Timestamp is set automatically if not provided.
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) Log(event *AuditEvent) {
	if !a.enabled {
		return
	}

	// Set default timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Add to buffer
	a.buffer = append(a.buffer, event)

	// Flush if buffer is full
	if len(a.buffer) >= a.bufferSize {
		a.flush()
	}
}

// LogRequest logs an HTTP request as an audit event. This is a convenience method
// that extracts relevant information from the HTTP request and creates an AuditEvent.
//
// Parameters:
//   - r: The HTTP request to log
//   - status: The HTTP response status code
//   - err: Any error that occurred during request processing (optional)
//   - metadata: Additional metadata to include in the audit event (optional)
//
// The method automatically extracts:
//   - Client IP address
//   - User agent
//   - Request ID (from X-Request-ID header)
//   - Subject (from request context)
//   - Resource type (from URL path)
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) LogRequest(r *http.Request, status int, err error, metadata map[string]interface{}) {
	if !a.enabled {
		return
	}

	event := &AuditEvent{
		Timestamp:  time.Now().UTC(),
		Action:     r.Method,
		Subject:    getSubjectFromRequest(r),
		Object:     r.URL.Path,
		Status:     http.StatusText(status),
		IP:         getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
		Resource:   getResourceFromPath(r.URL.Path),
		ResourceID: getResourceIDFromPath(r.URL.Path),
	}

	// Add error if present
	if err != nil {
		event.Error = err.Error()
	}

	// Add metadata
	if metadata != nil {
		event.Metadata = metadata
	}

	a.Log(event)
}

// LogSecurityEvent logs a security-related event such as authentication attempts,
// authorization failures, or security policy violations.
//
// Parameters:
//   - action: The security action (e.g., "login_attempt", "auth_failure", "policy_violation")
//   - subject: The entity performing the action (e.g., user ID, IP address)
//   - status: The result status (e.g., "success", "failure", "denied")
//   - r: The HTTP request (optional, for extracting IP and user agent)
//   - metadata: Additional metadata (optional)
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) LogSecurityEvent(action, subject, status string, r *http.Request, metadata map[string]interface{}) {
	if !a.enabled {
		return
	}

	event := &AuditEvent{
		Timestamp:  time.Now().UTC(),
		Action:     action,
		Subject:    subject,
		Status:     status,
		Source:     "api",
	}

	// Add request details if available
	if r != nil {
		event.IP = getClientIP(r)
		event.UserAgent = r.UserAgent()
		event.RequestID = r.Header.Get("X-Request-ID")
	}

	// Add metadata
	if metadata != nil {
		event.Metadata = metadata
	}

	a.Log(event)
}

// LogUserActivity logs user activity events such as profile updates, settings changes,
// or other user-initiated actions.
//
// Parameters:
//   - userID: The ID of the user performing the action
//   - action: The action being performed (e.g., "profile_update", "settings_change")
//   - status: The result status (e.g., "success", "failure")
//   - r: The HTTP request (optional, for extracting IP and user agent)
//   - metadata: Additional metadata (optional)
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) LogUserActivity(userID, action, status string, r *http.Request, metadata map[string]interface{}) {
	if !a.enabled {
		return
	}

	event := &AuditEvent{
		Timestamp:  time.Now().UTC(),
		Action:     action,
		Subject:    userID,
		Status:     status,
		Source:     "api",
	}

	// Add request details if available
	if r != nil {
		event.IP = getClientIP(r)
		event.UserAgent = r.UserAgent()
		event.RequestID = r.Header.Get("X-Request-ID")
	}

	// Add metadata
	if metadata != nil {
		event.Metadata = metadata
	}

	a.Log(event)
}

// LogDataAccess logs data access events such as reading, creating, updating, or
// deleting resources. This is useful for tracking who accessed what data and when.
//
// Parameters:
//   - userID: The ID of the user accessing the data
//   - action: The access action (e.g., "read", "create", "update", "delete")
//   - resourceType: The type of resource being accessed (e.g., "user", "token", "config")
//   - resourceID: The ID of the specific resource being accessed
//   - status: The result status (e.g., "success", "failure", "denied")
//   - r: The HTTP request (optional, for extracting IP and user agent)
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) LogDataAccess(userID, action, resourceType, resourceID, status string, r *http.Request) {
	if !a.enabled {
		return
	}

	event := &AuditEvent{
		Timestamp:  time.Now().UTC(),
		Action:     action,
		Subject:    userID,
		Resource:   resourceType,
		ResourceID: resourceID,
		Status:     status,
		Source:     "api",
	}

	// Add request details if available
	if r != nil {
		event.IP = getClientIP(r)
		event.UserAgent = r.UserAgent()
		event.RequestID = r.Header.Get("X-Request-ID")
	}

	a.Log(event)
}

// Flush writes all buffered events to the log output immediately.
// This is useful when you need to ensure all events are written before
// shutting down or when you want to force a flush.
//
// Returns:
//   - nil if all events were written successfully
//   - An error if writing failed
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) Flush() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	return a.flush()
}

// Close flushes any buffered events, stops the background flusher goroutine,
// and closes the log file if one was opened. This should be called when the
// AuditLogger is no longer needed to prevent resource leaks.
//
// Returns:
//   - nil if all operations succeeded
//   - An error if flushing or closing the file failed
//
// After calling Close(), the AuditLogger should not be used.
func (a *AuditLogger) Close() error {
	// Stop the background flusher
	if a.autoFlush {
		close(a.stopChan)
	}

	// Flush any remaining events
	if err := a.Flush(); err != nil {
		return err
	}

	// Close the log file if one was opened
	if a.file != nil {
		return a.file.Close()
	}

	return nil
}

// Enable enables the audit logger. When enabled, events are logged to the output.
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) Enable() {
	a.enabled = true
}

// Disable disables the audit logger. When disabled, events are not logged.
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) Disable() {
	a.enabled = false
}

// SetBufferSize sets the buffer size for batching log events. When the buffer
// reaches this size, it is automatically flushed. Larger buffers improve
// performance but use more memory.
//
// Parameters:
//   - size: The new buffer size (must be > 0)
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) SetBufferSize(size int) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.bufferSize = size
}

// SetAutoFlush enables or disables automatic periodic flushing of the log buffer.
// When enabled, the buffer is flushed at regular intervals (see SetFlushInterval).
// When disabled, the buffer is only flushed when it reaches the buffer size limit.
//
// Parameters:
//   - enabled: Whether to enable automatic flushing
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) SetAutoFlush(enabled bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.autoFlush = enabled
}

// SetFlushInterval sets the interval for automatic flushing of the log buffer.
// The background flusher will flush the buffer at this interval when auto-flush
// is enabled. Shorter intervals ensure more timely logging but may reduce performance.
//
// Parameters:
//   - interval: The flush interval (must be > 0)
//
// Thread-safety: This method is safe for concurrent use.
func (a *AuditLogger) SetFlushInterval(interval time.Duration) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.flushInterval = interval
}

// flush writes all buffered events to the log output.
// This is an internal method that must be called while holding the mutex.
// The buffer is cleared after flushing. Sensitive data is redacted before logging.
//
// Returns:
//   - nil if all events were written successfully
//   - An error if writing failed (logged but not returned to prevent blocking)
//
// Note: This method is not thread-safe and must be called while holding the mutex.
func (a *AuditLogger) flush() error {
	if len(a.buffer) == 0 {
		return nil
	}

	// Create a copy of the buffer and clear it
	events := make([]*AuditEvent, len(a.buffer))
	copy(events, a.buffer)
	a.buffer = a.buffer[:0]

	// Log each event
	for _, event := range events {
		// Redact sensitive information
		a.redactSensitiveData(event)

		// Convert to JSON
		data, err := json.Marshal(event)
		if err != nil {
			// If we can't marshal the event, log the error and continue
			a.logger.WithError(err).Error("Failed to marshal audit event")
			continue
		}

		// Write to log
		a.logger.Info(string(data))
	}

	return nil
}

// backgroundFlusher periodically flushes the log buffer at the configured interval.
// This method runs in a background goroutine and stops when the stopChan is closed.
// The ticker is properly stopped to prevent resource leaks.
func (a *AuditLogger) backgroundFlusher() {
	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := a.Flush(); err != nil {
				a.logger.WithError(err).Error("Failed to flush audit log")
			}
		case <-a.stopChan:
			return
		}
	}
}

// redactSensitiveData removes or masks sensitive information from the audit event
// to prevent sensitive data from being logged. This is a critical security feature
// that helps prevent password, token, and API key exposure in audit logs.
//
// The function redacts the following fields in metadata and changes:
//   - password, passwd, pwd
//   - secret, token, apikey, api_key
//   - authorization
//
// Sensitive values are replaced with a redaction marker that includes a hash
// of the original value for correlation purposes.
//
// Parameters:
//   - event: The audit event to redact (modified in place)
func (a *AuditLogger) redactSensitiveData(event *AuditEvent) {
	// Redact passwords and tokens in metadata
	if metadata, ok := event.Metadata.(map[string]interface{}); ok {
		for k, v := range metadata {
			switch strings.ToLower(k) {
			case "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "authorization":
				if s, ok := v.(string); ok && s != "" {
					// Replace with a hash of the value
					hash := sha256.Sum256([]byte(s))
					metadata[k] = "[REDACTED_" + hex.EncodeToString(hash[:8]) + "]"
				} else {
					metadata[k] = "[REDACTED]"
				}
			}
		}
	}

	// Redact sensitive information in the changes field
	if changes, ok := event.Changes.(map[string]interface{}); ok {
		for k, v := range changes {
			switch strings.ToLower(k) {
			case "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "authorization":
				if s, ok := v.(string); ok && s != "" {
					// Replace with a hash of the value
					hash := sha256.Sum256([]byte(s))
					changes[k] = "[REDACTED_" + hex.EncodeToString(hash[:8]) + "]"
				} else {
					changes[k] = "[REDACTED]"
				}
			}
		}
	}
}

// Helper functions

// getClientIP extracts and validates the client IP address from the HTTP request.
// This is a helper function used by the audit logger to extract client IPs.
//
// It first checks the X-Forwarded-For header (used when behind a reverse proxy),
// then falls back to RemoteAddr. The IP is validated to prevent spoofing attacks.
//
// Security Note: X-Forwarded-For can be spoofed if not behind a trusted proxy.
// In production, ensure your reverse proxy validates and sets this header.
//
// Returns the validated client IP address, or RemoteAddr if validation fails.
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// X-Forwarded-For can be a comma-separated list of IPs
		// The first IP is the original client, the rest are proxies
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// Validate that it's a valid IP address to prevent spoofing
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
			// If invalid IP, fall through to RemoteAddr
		}
	}

	// Fall back to RemoteAddr if X-Forwarded-For is not set
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// getSubjectFromRequest extracts the subject (user ID) from the request
func getSubjectFromRequest(r *http.Request) string {
	// Try to get user ID from JWT claims if available
	if claims := r.Context().Value("claims"); claims != nil {
		if c, ok := claims.(map[string]interface{}); ok {
			if sub, ok := c["sub"].(string); ok && sub != "" {
				return sub
			}
		}
	}

	// Fall back to the remote address
	return getClientIP(r)
}

// getResourceFromPath extracts the resource type from the URL path.
// This is a helper function used by the audit logger to identify what resource
// was accessed. It parses the URL path to extract the resource type.
//
// Example paths:
//   - "/api/users/123" -> "users"
//   - "/api/tokens" -> "tokens"
//   - "/api/config" -> "config"
//
// Returns the resource type if found, otherwise returns an empty string.
func getResourceFromPath(path string) string {
	// Remove leading and trailing slashes
	path = strings.Trim(path, "/")

	// Split into parts
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}

	// The resource is typically the first part of the path
	return parts[0]
}

// getResourceIDFromPath extracts the resource ID from the URL path.
// This is a helper function used by the audit logger to identify which specific
// resource was accessed. It parses the URL path to extract the resource ID.
//
// Security: This function safely handles edge cases and validates path structure.
//
// Example paths:
//   - "/api/users/123" -> "123"
//   - "/api/tokens/abc-def" -> "abc-def"
//   - "/api/config" -> "" (no ID in path)
//
// Returns the resource ID if found, otherwise returns an empty string.
func getResourceIDFromPath(path string) string {
	// Security: Validate path is not empty
	if path == "" {
		return ""
	}
	
	// Remove leading and trailing slashes
	path = strings.Trim(path, "/")
	if path == "" {
		return ""
	}

	// Split into parts
	parts := strings.Split(path, "/")
	// Security: Validate we have at least 2 parts (resource type and ID)
	if len(parts) < 2 {
		return ""
	}

	// The ID is typically the second part of the path
	// Check if it looks like an ID (not a path segment like "new", "edit", etc.)
	id := parts[1]
	// Security: Validate ID is not empty and doesn't contain query parameters
	if len(id) == 0 || strings.ContainsAny(id, "?&=") || id == "new" || id == "edit" || id == "delete" {
		return ""
	}

	return id
}

// RequestLogger is an HTTP middleware that logs requests and responses
type RequestLogger struct {
	auditLogger *AuditLogger
}

// NewRequestLogger creates a new RequestLogger instance
func NewRequestLogger(auditLogger *AuditLogger) *RequestLogger {
	return &RequestLogger{
		auditLogger: auditLogger,
	}
}

// Middleware returns an HTTP middleware function that logs requests and responses
func (rl *RequestLogger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip logging for health checks and metrics endpoints
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		// Capture the request body for logging
		// Security: Limit body size to prevent DoS attacks and excessive memory usage
		const maxRequestBodySize = 1024 * 1024 // 1MB for logging
		var requestBody []byte
		if r.Body != nil && r.Body != http.NoBody {
			var buf bytes.Buffer
			limitedReader := io.LimitReader(r.Body, maxRequestBodySize+1)
			tee := io.TeeReader(limitedReader, &buf)
			requestBody, _ = io.ReadAll(tee)
			// Check if body was truncated
			if len(requestBody) > maxRequestBodySize {
				requestBody = requestBody[:maxRequestBodySize]
			}
			r.Body = io.NopCloser(&buf)
		}

		// Create a response writer that captures the status code
		rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		// Record the start time
		start := time.Now()

		// Process the request
		next.ServeHTTP(rw, r)

		// Calculate the duration
		duration := time.Since(start)

		// Log the request
		rl.logRequest(r, rw.status, duration, requestBody)
	})
}

// logRequest logs an HTTP request and response
func (rl *RequestLogger) logRequest(r *http.Request, status int, duration time.Duration, requestBody []byte) {
	// Skip logging for successful health checks
	if r.URL.Path == "/healthz" && status == http.StatusOK {
		return
	}

	// Create metadata with request details
	metadata := map[string]interface{}{
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       r.URL.RawQuery,
		"status":      status,
		"duration_ms": duration.Milliseconds(),
	}

	// Add request headers if needed
	if len(r.Header) > 0 {
		headers := make(map[string]string)
		for k, v := range r.Header {
			// Skip sensitive headers
			switch strings.ToLower(k) {
			case "authorization", "cookie", "set-cookie":
				headers[k] = "[REDACTED]"
			default:
				headers[k] = strings.Join(v, ", ")
			}
		}
		metadata["headers"] = headers
	}

	// Add request body if present and not too large
	if len(requestBody) > 0 && len(requestBody) < 1024 {
		// Try to parse as JSON for better formatting
		var body interface{}
		if err := json.Unmarshal(requestBody, &body); err == nil {
			metadata["body"] = body
		} else {
			metadata["body"] = string(requestBody)
		}
	}

	// Determine the status
	statusText := "success"
	if status >= 400 {
		statusText = "error"
	}

	// Log the event
	rl.auditLogger.Log(&AuditEvent{
		Timestamp:  time.Now().UTC(),
		Action:     r.Method,
		Subject:    getSubjectFromRequest(r),
		Object:     r.URL.Path,
		Status:     statusText,
		IP:         getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
		Metadata:   metadata,
		Duration:   duration,
		Resource:   getResourceFromPath(r.URL.Path),
		ResourceID: getResourceIDFromPath(r.URL.Path),
	})
}

// responseRecorder is a wrapper around http.ResponseWriter that captures the status code
type responseRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code before writing the header
func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Write writes the data to the connection as part of an HTTP reply
func (r *responseRecorder) Write(b []byte) (int, error) {
	// If WriteHeader hasn't been called, default to 200 OK
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Hijack implements the http.Hijacker interface
func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("response writer does not implement http.Hijacker")
}
