package instance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultManager_GetVersionInfo_ReturnsCurrentVersion(t *testing.T) {
	m := &DefaultManager{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := m.GetVersionInfo(ctx)
	require.NoError(t, err)

	// CurrentVersion should always be set
	assert.NotEmpty(t, info.CurrentVersion)
}

func TestDefaultManager_GetVersionInfo_CachesResults(t *testing.T) {
	m := &DefaultManager{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx := context.Background()

	// First call
	info1, err := m.GetVersionInfo(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, info1.CurrentVersion)

	// Second call should use cache
	info2, err := m.GetVersionInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, info1.CurrentVersion, info2.CurrentVersion)
}

func TestDefaultManager_FetchGitHubRelease_ParsesTagName(t *testing.T) {
	tests := []struct {
		name        string
		tagName     string
		expected    string
		shouldError bool
	}{
		{
			name:     "tag with v prefix",
			tagName:  "v1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "tag without v prefix",
			tagName:  "1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "tag with prerelease",
			tagName:  "v2.0.0-beta.1",
			expected: "2.0.0-beta.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(githubRelease{TagName: tc.tagName})
			}))
			defer server.Close()

			m := &DefaultManager{
				httpClient: &http.Client{Timeout: 5 * time.Second},
			}

			version, err := m.fetchGitHubRelease(context.Background(), server.URL)

			if tc.shouldError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, version)
			}
		})
	}
}

func TestDefaultManager_FetchGitHubRelease_HandlesErrors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			body:       `{"message": "Not Found"}`,
		},
		{
			name:       "rate limited",
			statusCode: http.StatusForbidden,
			body:       `{"message": "API rate limit exceeded"}`,
		},
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			body:       `{"message": "Internal Server Error"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			m := &DefaultManager{
				httpClient: &http.Client{Timeout: 5 * time.Second},
			}

			_, err := m.fetchGitHubRelease(context.Background(), server.URL)
			assert.Error(t, err)
		})
	}
}

func TestDefaultManager_FetchGitHubRelease_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json}`))
	}))
	defer server.Close()

	m := &DefaultManager{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	_, err := m.fetchGitHubRelease(context.Background(), server.URL)
	assert.Error(t, err)
}

func TestDefaultManager_FetchGitHubRelease_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(githubRelease{TagName: "v1.0.0"})
	}))
	defer server.Close()

	m := &DefaultManager{
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := m.fetchGitHubRelease(ctx, server.URL)
	assert.Error(t, err)
}
