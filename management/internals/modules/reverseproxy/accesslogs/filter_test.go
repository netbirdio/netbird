package accesslogs

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessLogFilter_ParseFromRequest(t *testing.T) {
	tests := []struct {
		name             string
		queryParams      map[string]string
		expectedPage     int
		expectedPageSize int
	}{
		{
			name:             "default values when no params provided",
			queryParams:      map[string]string{},
			expectedPage:     1,
			expectedPageSize: DefaultPageSize,
		},
		{
			name: "valid page and page_size",
			queryParams: map[string]string{
				"page":      "2",
				"page_size": "25",
			},
			expectedPage:     2,
			expectedPageSize: 25,
		},
		{
			name: "page_size exceeds max, should cap at MaxPageSize",
			queryParams: map[string]string{
				"page":      "1",
				"page_size": "200",
			},
			expectedPage:     1,
			expectedPageSize: MaxPageSize,
		},
		{
			name: "invalid page number, should use default",
			queryParams: map[string]string{
				"page":      "invalid",
				"page_size": "10",
			},
			expectedPage:     1,
			expectedPageSize: 10,
		},
		{
			name: "invalid page_size, should use default",
			queryParams: map[string]string{
				"page":      "2",
				"page_size": "invalid",
			},
			expectedPage:     2,
			expectedPageSize: DefaultPageSize,
		},
		{
			name: "zero page number, should use default",
			queryParams: map[string]string{
				"page":      "0",
				"page_size": "10",
			},
			expectedPage:     1,
			expectedPageSize: 10,
		},
		{
			name: "negative page number, should use default",
			queryParams: map[string]string{
				"page":      "-1",
				"page_size": "10",
			},
			expectedPage:     1,
			expectedPageSize: 10,
		},
		{
			name: "zero page_size, should use default",
			queryParams: map[string]string{
				"page":      "1",
				"page_size": "0",
			},
			expectedPage:     1,
			expectedPageSize: DefaultPageSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			q := req.URL.Query()
			for key, value := range tt.queryParams {
				q.Set(key, value)
			}
			req.URL.RawQuery = q.Encode()

			filter := &AccessLogFilter{}
			filter.ParseFromRequest(req)

			assert.Equal(t, tt.expectedPage, filter.Page, "Page mismatch")
			assert.Equal(t, tt.expectedPageSize, filter.PageSize, "PageSize mismatch")
		})
	}
}

func TestAccessLogFilter_GetOffset(t *testing.T) {
	tests := []struct {
		name           string
		page           int
		pageSize       int
		expectedOffset int
	}{
		{
			name:           "first page",
			page:           1,
			pageSize:       50,
			expectedOffset: 0,
		},
		{
			name:           "second page",
			page:           2,
			pageSize:       50,
			expectedOffset: 50,
		},
		{
			name:           "third page with page size 25",
			page:           3,
			pageSize:       25,
			expectedOffset: 50,
		},
		{
			name:           "page 10 with page size 10",
			page:           10,
			pageSize:       10,
			expectedOffset: 90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &AccessLogFilter{
				Page:     tt.page,
				PageSize: tt.pageSize,
			}

			offset := filter.GetOffset()
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

func TestAccessLogFilter_GetLimit(t *testing.T) {
	filter := &AccessLogFilter{
		Page:     2,
		PageSize: 25,
	}

	limit := filter.GetLimit()
	assert.Equal(t, 25, limit, "GetLimit should return PageSize")
}

func TestAccessLogFilter_ParseFromRequest_FilterParams(t *testing.T) {
	startDate := "2024-01-15T10:30:00Z"
	endDate := "2024-01-16T15:45:00Z"

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	q := req.URL.Query()
	q.Set("search", "test query")
	q.Set("source_ip", "192.168.1.1")
	q.Set("host", "example.com")
	q.Set("path", "/api/users")
	q.Set("user_id", "user123")
	q.Set("user_email", "user@example.com")
	q.Set("user_name", "John Doe")
	q.Set("method", "GET")
	q.Set("status", "success")
	q.Set("status_code", "200")
	q.Set("start_date", startDate)
	q.Set("end_date", endDate)
	req.URL.RawQuery = q.Encode()

	filter := &AccessLogFilter{}
	filter.ParseFromRequest(req)

	require.NotNil(t, filter.Search)
	assert.Equal(t, "test query", *filter.Search)

	require.NotNil(t, filter.SourceIP)
	assert.Equal(t, "192.168.1.1", *filter.SourceIP)

	require.NotNil(t, filter.Host)
	assert.Equal(t, "example.com", *filter.Host)

	require.NotNil(t, filter.Path)
	assert.Equal(t, "/api/users", *filter.Path)

	require.NotNil(t, filter.UserID)
	assert.Equal(t, "user123", *filter.UserID)

	require.NotNil(t, filter.UserEmail)
	assert.Equal(t, "user@example.com", *filter.UserEmail)

	require.NotNil(t, filter.UserName)
	assert.Equal(t, "John Doe", *filter.UserName)

	require.NotNil(t, filter.Method)
	assert.Equal(t, "GET", *filter.Method)

	require.NotNil(t, filter.Status)
	assert.Equal(t, "success", *filter.Status)

	require.NotNil(t, filter.StatusCode)
	assert.Equal(t, 200, *filter.StatusCode)

	require.NotNil(t, filter.StartDate)
	expectedStart, _ := time.Parse(time.RFC3339, startDate)
	assert.Equal(t, expectedStart, *filter.StartDate)

	require.NotNil(t, filter.EndDate)
	expectedEnd, _ := time.Parse(time.RFC3339, endDate)
	assert.Equal(t, expectedEnd, *filter.EndDate)
}

func TestAccessLogFilter_ParseFromRequest_EmptyFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	filter := &AccessLogFilter{}
	filter.ParseFromRequest(req)

	assert.Nil(t, filter.Search)
	assert.Nil(t, filter.SourceIP)
	assert.Nil(t, filter.Host)
	assert.Nil(t, filter.Path)
	assert.Nil(t, filter.UserID)
	assert.Nil(t, filter.UserEmail)
	assert.Nil(t, filter.UserName)
	assert.Nil(t, filter.Method)
	assert.Nil(t, filter.Status)
	assert.Nil(t, filter.StatusCode)
	assert.Nil(t, filter.StartDate)
	assert.Nil(t, filter.EndDate)
}

func TestAccessLogFilter_ParseFromRequest_InvalidFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	q := req.URL.Query()
	q.Set("status_code", "invalid")
	q.Set("start_date", "not-a-date")
	q.Set("end_date", "2024-99-99")
	req.URL.RawQuery = q.Encode()

	filter := &AccessLogFilter{}
	filter.ParseFromRequest(req)

	assert.Nil(t, filter.StatusCode, "invalid status_code should be nil")
	assert.Nil(t, filter.StartDate, "invalid start_date should be nil")
	assert.Nil(t, filter.EndDate, "invalid end_date should be nil")
}

func TestParsePositiveInt(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue int
		expected     int
	}{
		{"empty string", "", 10, 10},
		{"valid positive int", "25", 10, 25},
		{"zero", "0", 10, 10},
		{"negative", "-5", 10, 10},
		{"invalid string", "abc", 10, 10},
		{"float", "3.14", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePositiveInt(tt.input, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseOptionalString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *string
	}{
		{"empty string", "", nil},
		{"valid string", "hello", strPtr("hello")},
		{"whitespace", "  ", strPtr("  ")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOptionalString(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestParseOptionalInt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *int
	}{
		{"empty string", "", nil},
		{"valid positive int", "42", intPtr(42)},
		{"zero", "0", nil},
		{"negative", "-10", nil},
		{"invalid string", "abc", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOptionalInt(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestParseOptionalRFC3339(t *testing.T) {
	validDate := "2024-01-15T10:30:00Z"
	expectedTime, _ := time.Parse(time.RFC3339, validDate)

	tests := []struct {
		name     string
		input    string
		expected *time.Time
	}{
		{"empty string", "", nil},
		{"valid RFC3339", validDate, &expectedTime},
		{"invalid format", "2024-01-15", nil},
		{"invalid date", "not-a-date", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOptionalRFC3339(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

// Helper functions for creating pointers
func strPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
