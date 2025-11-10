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

// AuditEvent represents a security-relevant event that should be logged
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
	ResourceID  string        `json:esource_id,omitempty"`  // ID of the affected resource
	Changes     interface{}   `json:"changes,omitempty"`      // What changed (for update/delete operations)
}

// AuditLogger is responsible for logging security-relevant events
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

// NewAuditLogger creates a new AuditLogger instance
// If logFile is not empty, logs will be written to the specified file in addition to the default output
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
		dir := filepath.Dir(logFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %v", err)
		}

		// Open the log file in append mode, create it if it doesn't exist
		file, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

// Log logs a new audit event
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

// LogRequest logs an HTTP request as an audit event
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

// LogSecurityEvent logs a security-related event
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

// LogUserActivity logs user activity
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

// LogDataAccess logs data access events
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

// Flush writes all buffered events to the log
func (a *AuditLogger) Flush() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	return a.flush()
}

// Close flushes any buffered events and closes the log file if one was opened
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

// Enable enables the audit logger
func (a *AuditLogger) Enable() {
	a.enabled = true
}

// Disable disables the audit logger
func (a *AuditLogger) Disable() {
	a.enabled = false
}

// SetBufferSize sets the buffer size for batching log events
func (a *AuditLogger) SetBufferSize(size int) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.bufferSize = size
}

// SetAutoFlush enables or disables automatic flushing of the log buffer
func (a *AuditLogger) SetAutoFlush(enabled bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.autoFlush = enabled
}

// SetFlushInterval sets the interval for automatic flushing of the log buffer
func (a *AuditLogger) SetFlushInterval(interval time.Duration) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.flushInterval = interval
}

// flush writes all buffered events to the log
// Caller must hold the mutex
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

// backgroundFlusher periodically flushes the log buffer
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

// redactSensitiveData removes or masks sensitive information from the event
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

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		// X-Forwarded-For can be a comma-separated list of IPs
		// The first IP is the original client, the rest are proxies
		ips := strings.Split(forwardedFor, ",")
		if len(tips) > 0 {
			return strings.TrimSpace(tips[0])
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

// getResourceFromPath extracts the resource type from the URL path
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

// getResourceIDFromPath extracts the resource ID from the URL path
func getResourceIDFromPath(path string) string {
	// Remove leading and trailing slashes
	path = strings.Trim(path, "/")

	// Split into parts
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}

	// The ID is typically the second part of the path
	// Check if it looks like an ID (not a path segment like "new", "edit", etc.)
	id := parts[1]
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
		var requestBody []byte
		if r.Body != nil && r.Body != http.NoBody {
			var buf bytes.Buffer
			tee := io.TeeReader(r.Body, &buf)
			requestBody, _ = io.ReadAll(tee)
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
