package reverseproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	log "github.com/sirupsen/logrus"
)

var (
	// Global map to store callbacks per service ID
	callbackRegistry = make(map[string]RequestDataCallback)
	callbackMu       sync.RWMutex
)

// RegisterCallback registers a callback for a specific service ID
func RegisterCallback(serviceID string, callback RequestDataCallback) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	callbackRegistry[serviceID] = callback
}

// UnregisterCallback removes a callback for a specific service ID
func UnregisterCallback(serviceID string) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	delete(callbackRegistry, serviceID)
}

// getCallback retrieves the callback for a service ID
func getCallback(serviceID string) RequestDataCallback {
	callbackMu.RLock()
	defer callbackMu.RUnlock()
	return callbackRegistry[serviceID]
}

func init() {
	caddy.RegisterModule(CallbackWriter{})
}

// CallbackWriter is a Caddy log writer module that sends request data via callback
type CallbackWriter struct {
	ServiceID string `json:"service_id,omitempty"`
}

// CaddyModule returns the Caddy module information
func (CallbackWriter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.writers.callback",
		New: func() caddy.Module { return new(CallbackWriter) },
	}
}

// Provision sets up the callback writer
func (cw *CallbackWriter) Provision(ctx caddy.Context) error {
	log.Infof("CallbackWriter.Provision called for service_id: %s", cw.ServiceID)
	return nil
}

// String returns a human-readable representation of the writer
func (cw *CallbackWriter) String() string {
	return fmt.Sprintf("callback writer for service %s", cw.ServiceID)
}

// WriterKey returns a unique key for this writer configuration
func (cw *CallbackWriter) WriterKey() string {
	return "callback_" + cw.ServiceID
}

// OpenWriter opens the writer
func (cw *CallbackWriter) OpenWriter() (io.WriteCloser, error) {
	log.Infof("CallbackWriter.OpenWriter called for service_id: %s", cw.ServiceID)
	writer := &LogWriter{
		serviceID: cw.ServiceID,
	}
	log.Infof("Created LogWriter instance: %p for service_id: %s", writer, cw.ServiceID)
	return writer, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (cw *CallbackWriter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		cw.ServiceID = d.Val()
	}
	return nil
}

// Ensure CallbackWriter implements the required interfaces
var (
	_ caddy.Provisioner     = (*CallbackWriter)(nil)
	_ caddy.WriterOpener    = (*CallbackWriter)(nil)
	_ caddyfile.Unmarshaler = (*CallbackWriter)(nil)
)

// LogWriter is a custom io.Writer that parses Caddy's structured JSON logs
// and extracts request metrics to send via callback
type LogWriter struct {
	serviceID string
}

// NewLogWriter creates a new log writer with the given service ID
func NewLogWriter(serviceID string) *LogWriter {
	return &LogWriter{
		serviceID: serviceID,
	}
}

// Write implements io.Writer
func (lw *LogWriter) Write(p []byte) (n int, err error) {
	// DEBUG: Log that we received data
	log.Infof("LogWriter.Write called with %d bytes for service_id: %s", len(p), lw.serviceID)
	log.Debugf("LogWriter content: %s", string(p))

	// Caddy writes one JSON object per line
	// Parse the JSON to extract request metrics
	var logEntry map[string]interface{}
	if err := json.Unmarshal(p, &logEntry); err != nil {
		// Not JSON or malformed, skip
		log.Debugf("Failed to unmarshal JSON: %v", err)
		return len(p), nil
	}

	// Caddy access logs have a nested "request" object
	// Check if this is an access log entry by looking for "request" field
	requestObj, hasRequest := logEntry["request"]
	if !hasRequest {
		log.Debugf("Not an access log entry (no 'request' field)")
		return len(p), nil
	}

	request, ok := requestObj.(map[string]interface{})
	if !ok {
		log.Debugf("'request' field is not a map")
		return len(p), nil
	}

	// Extract fields
	data := &RequestData{
		ServiceID: lw.serviceID,
	}

	// Extract method from request object
	if method, ok := request["method"].(string); ok {
		data.Method = method
	}

	// Extract host from request object and strip port
	if host, ok := request["host"].(string); ok {
		// Strip port from host (e.g., "test.netbird.io:54321" -> "test.netbird.io")
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			data.Host = host[:idx]
		} else {
			data.Host = host
		}
	}

	// Extract path (uri field) from request object
	if uri, ok := request["uri"].(string); ok {
		data.Path = uri
	}

	// Extract status code from top-level
	if status, ok := logEntry["status"].(float64); ok {
		data.ResponseCode = int32(status)
	}

	// Extract duration (in seconds, convert to milliseconds) from top-level
	if duration, ok := logEntry["duration"].(float64); ok {
		data.DurationMs = int64(duration * 1000)
	}

	// Extract source IP from request object - try multiple fields
	if clientIP, ok := request["client_ip"].(string); ok {
		data.SourceIP = clientIP
	} else if remoteIP, ok := request["remote_ip"].(string); ok {
		data.SourceIP = remoteIP
	} else if remoteAddr, ok := request["remote_addr"].(string); ok {
		// remote_addr is in "IP:port" format
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			data.SourceIP = remoteAddr[:idx]
		} else {
			data.SourceIP = remoteAddr
		}
	}

	// Call callback if set and we have valid data
	callback := getCallback(lw.serviceID)
	if callback != nil && data.Method != "" {
		log.Infof("Calling callback for request: %s %s", data.Method, data.Path)
		go func() {
			// Run in goroutine to avoid blocking log writes
			callback(data)
		}()
	} else {
		log.Warnf("No callback registered for service_id: %s", lw.serviceID)
	}

	log.WithFields(log.Fields{
		"service_id":  data.ServiceID,
		"method":      data.Method,
		"host":        data.Host,
		"path":        data.Path,
		"status":      data.ResponseCode,
		"duration_ms": data.DurationMs,
		"source_ip":   data.SourceIP,
	}).Info("Request logged via callback writer")

	return len(p), nil
}

// Close implements io.Closer (no-op for our use case)
func (lw *LogWriter) Close() error {
	return nil
}

// Ensure LogWriter implements io.WriteCloser
var _ io.WriteCloser = (*LogWriter)(nil)
