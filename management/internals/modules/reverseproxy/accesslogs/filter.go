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

	f.Page = 1
	if pageStr := queryParams.Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			f.Page = page
		}
	}

	f.PageSize = DefaultPageSize
	if pageSizeStr := queryParams.Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 {
			f.PageSize = pageSize
			if f.PageSize > MaxPageSize {
				f.PageSize = MaxPageSize
			}
		}
	}

	if search := queryParams.Get("search"); search != "" {
		f.Search = &search
	}

	if sourceIP := queryParams.Get("source_ip"); sourceIP != "" {
		f.SourceIP = &sourceIP
	}

	if host := queryParams.Get("host"); host != "" {
		f.Host = &host
	}

	if path := queryParams.Get("path"); path != "" {
		f.Path = &path
	}

	if userID := queryParams.Get("user_id"); userID != "" {
		f.UserID = &userID
	}

	if userEmail := queryParams.Get("user_email"); userEmail != "" {
		f.UserEmail = &userEmail
	}

	if userName := queryParams.Get("user_name"); userName != "" {
		f.UserName = &userName
	}

	if method := queryParams.Get("method"); method != "" {
		f.Method = &method
	}

	if status := queryParams.Get("status"); status != "" {
		f.Status = &status
	}

	if statusCodeStr := queryParams.Get("status_code"); statusCodeStr != "" {
		if statusCode, err := strconv.Atoi(statusCodeStr); err == nil && statusCode > 0 {
			f.StatusCode = &statusCode
		}
	}

	if startDate := queryParams.Get("start_date"); startDate != "" {
		parsedStartDate, err := time.Parse(time.RFC3339, startDate)
		if err == nil {
			f.StartDate = &parsedStartDate
		}
	}

	if endDate := queryParams.Get("end_date"); endDate != "" {
		parsedEndDate, err := time.Parse(time.RFC3339, endDate)
		if err == nil {
			f.EndDate = &parsedEndDate
		}
	}
}

// GetOffset calculates the database offset for pagination
func (f *AccessLogFilter) GetOffset() int {
	return (f.Page - 1) * f.PageSize
}

// GetLimit returns the page size for database queries
func (f *AccessLogFilter) GetLimit() int {
	return f.PageSize
}
