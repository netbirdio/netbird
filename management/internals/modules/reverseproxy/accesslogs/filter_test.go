package accesslogs

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
