package accesslogs

import (
	"net/http"
	"strconv"
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
}

// ParseFromRequest parses pagination parameters from HTTP request query parameters
func (f *AccessLogFilter) ParseFromRequest(r *http.Request) {
	// Parse page number (default: 1)
	f.Page = 1
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			f.Page = page
		}
	}

	// Parse page size (default: DefaultPageSize, max: MaxPageSize)
	f.PageSize = DefaultPageSize
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 {
			f.PageSize = pageSize
			if f.PageSize > MaxPageSize {
				f.PageSize = MaxPageSize
			}
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
