package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of the application
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

// Check represents a health check
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Response represents the health check response
type Response struct {
	Status    Status           `json:"status"`
	Timestamp time.Time        `json:"timestamp"`
	Uptime    time.Duration    `json:"uptime_seconds"`
	Checks    map[string]Check `json:"checks,omitempty"`
}

// Checker is the interface for health checks
type Checker interface {
	Check() Check
}

// Handler manages health checks
type Handler struct {
	mu        sync.RWMutex
	checkers  map[string]Checker
	startTime time.Time
}

// NewHandler creates a new health check handler
func NewHandler() *Handler {
	return &Handler{
		checkers:  make(map[string]Checker),
		startTime: time.Now(),
	}
}

// RegisterChecker registers a health checker
func (h *Handler) RegisterChecker(name string, checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers[name] = checker
}

// ServeHTTP handles health check requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	response := Response{
		Status:    StatusHealthy,
		Timestamp: time.Now(),
		Uptime:    time.Since(h.startTime),
		Checks:    make(map[string]Check),
	}

	// Run all health checks
	for name, checker := range h.checkers {
		check := checker.Check()
		response.Checks[name] = check

		// Update overall status
		if check.Status == StatusUnhealthy {
			response.Status = StatusUnhealthy
		} else if check.Status == StatusDegraded && response.Status != StatusUnhealthy {
			response.Status = StatusDegraded
		}
	}

	// Set HTTP status code based on health
	statusCode := http.StatusOK
	if response.Status == StatusUnhealthy {
		statusCode = http.StatusServiceUnavailable
	} else if response.Status == StatusDegraded {
		statusCode = http.StatusOK // Still return 200 for degraded
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// ReadinessHandler returns a simple readiness probe handler
func ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready"))
}

// LivenessHandler returns a simple liveness probe handler
func LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("alive"))
}
