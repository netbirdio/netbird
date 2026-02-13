package accesslogs

import (
	"net/http"
	"strconv"
	"time"
)

const (
	// DefaultPageSize is the default number of records per page
	DefaultPageSize = 50
	// MaxPageSize is the maximum number of records allowed per page
	MaxPageSize = 100
)

// AccessLogFilter holds pagination and filtering parameters for access logs
type AccessLogFilter struct {
	// Page is the current page number (1-indexed)
	Page int
	// PageSize is the number of records per page
	PageSize int

	// Filtering parameters
	Search     *string    // General search across log ID, host, path, source IP, and user fields
	SourceIP   *string    // Filter by source IP address
	Host       *string    // Filter by host header
	Path       *string    // Filter by request path (supports LIKE pattern)
	UserID     *string    // Filter by authenticated user ID
	UserEmail  *string    // Filter by user email (requires user lookup)
	UserName   *string    // Filter by user name (requires user lookup)
	Method     *string    // Filter by HTTP method
	Status     *string    // Filter by status: "success" (2xx/3xx) or "failed" (1xx/4xx/5xx)
	StatusCode *int       // Filter by HTTP status code
	StartDate  *time.Time // Filter by timestamp >= start_date
	EndDate    *time.Time // Filter by timestamp <= end_date
}

// ParseFromRequest parses pagination and filter parameters from HTTP request query parameters
func (f *AccessLogFilter) ParseFromRequest(r *http.Request) {
	queryParams := r.URL.Query()

	f.Page = parsePositiveInt(queryParams.Get("page"), 1)
	f.PageSize = min(parsePositiveInt(queryParams.Get("page_size"), DefaultPageSize), MaxPageSize)

	f.Search = parseOptionalString(queryParams.Get("search"))
	f.SourceIP = parseOptionalString(queryParams.Get("source_ip"))
	f.Host = parseOptionalString(queryParams.Get("host"))
	f.Path = parseOptionalString(queryParams.Get("path"))
	f.UserID = parseOptionalString(queryParams.Get("user_id"))
	f.UserEmail = parseOptionalString(queryParams.Get("user_email"))
	f.UserName = parseOptionalString(queryParams.Get("user_name"))
	f.Method = parseOptionalString(queryParams.Get("method"))
	f.Status = parseOptionalString(queryParams.Get("status"))
	f.StatusCode = parseOptionalInt(queryParams.Get("status_code"))
	f.StartDate = parseOptionalRFC3339(queryParams.Get("start_date"))
	f.EndDate = parseOptionalRFC3339(queryParams.Get("end_date"))
}

// parsePositiveInt parses a positive integer from a string, returning defaultValue if invalid
func parsePositiveInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	if val, err := strconv.Atoi(s); err == nil && val > 0 {
		return val
	}
	return defaultValue
}

// parseOptionalString returns a pointer to the string if non-empty, otherwise nil
func parseOptionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// parseOptionalInt parses an optional positive integer from a string
func parseOptionalInt(s string) *int {
	if s == "" {
		return nil
	}
	if val, err := strconv.Atoi(s); err == nil && val > 0 {
		v := val
		return &v
	}
	return nil
}

// parseOptionalRFC3339 parses an optional RFC3339 timestamp from a string
func parseOptionalRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}

// GetOffset calculates the database offset for pagination
func (f *AccessLogFilter) GetOffset() int {
	return (f.Page - 1) * f.PageSize
}

// GetLimit returns the page size for database queries
func (f *AccessLogFilter) GetLimit() int {
	return f.PageSize
}
