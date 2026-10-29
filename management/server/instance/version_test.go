package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRoundTripper implements http.RoundTripper for testing
type mockRoundTripper struct {
	callCount         atomic.Int32
	managementVersion string
	dashboardVersion  string
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.callCount.Add(1)

	var body string
	if strings.Contains(req.URL.String(), "pkgs.netbird.io") {
		// Plain text response for management version
		body = m.managementVersion
	} else if strings.Contains(req.URL.String(), "github.com") {
		// JSON response for dashboard version
		jsonResp, _ := json.Marshal(githubRelease{TagName: "v" + m.dashboardVersion})
		body = string(jsonResp)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}, nil
}

func TestDefaultManager_GetVersionInfo_ReturnsCurrentVersion(t *testing.T) {
	mockTransport := &mockRoundTripper{
		managementVersion: "0.65.0",
		dashboardVersion:  "2.10.0",
	}

	m := &DefaultManager{
		httpClient: &http.Client{Transport: mockTransport},
	}

	ctx := context.Background()

	info, err := m.GetVersionInfo(ctx)
	require.NoError(t, err)

	// CurrentVersion should always be set
	assert.NotEmpty(t, info.CurrentVersion)
	assert.Equal(t, "0.65.0", info.ManagementVersion)
	assert.Equal(t, "2.10.0", info.DashboardVersion)
	assert.Equal(t, int32(2), mockTransport.callCount.Load()) // 2 calls: management + dashboard
}

func TestDefaultManager_GetVersionInfo_CachesResults(t *testing.T) {
	mockTransport := &mockRoundTripper{
		managementVersion: "0.65.0",
		dashboardVersion:  "2.10.0",
	}

	m := &DefaultManager{
		httpClient: &http.Client{Transport: mockTransport},
	}

	ctx := context.Background()

	// First call
	info1, err := m.GetVersionInfo(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, info1.CurrentVersion)
	assert.Equal(t, "0.65.0", info1.ManagementVersion)

	initialCallCount := mockTransport.callCount.Load()

	// Second call should use cache (no additional HTTP calls)
	info2, err := m.GetVersionInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, info1.CurrentVersion, info2.CurrentVersion)
	assert.Equal(t, info1.ManagementVersion, info2.ManagementVersion)
	assert.Equal(t, info1.DashboardVersion, info2.DashboardVersion)

	// Verify no additional HTTP calls were made (cache was used)
	assert.Equal(t, initialCallCount, mockTransport.callCount.Load())
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

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		latestVersion  string
		expected       bool
	}{
		{
			name:           "latest is newer - minor version",
			currentVersion: "0.64.1",
			latestVersion:  "0.65.0",
			expected:       true,
		},
		{
			name:           "latest is newer - patch version",
			currentVersion: "0.64.1",
			latestVersion:  "0.64.2",
			expected:       true,
		},
		{
			name:           "latest is newer - major version",
			currentVersion: "0.64.1",
			latestVersion:  "1.0.0",
			expected:       true,
		},
		{
			name:           "versions are equal",
			currentVersion: "0.64.1",
			latestVersion:  "0.64.1",
			expected:       false,
		},
		{
			name:           "current is newer - minor version",
			currentVersion: "0.65.0",
			latestVersion:  "0.64.1",
			expected:       false,
		},
		{
			name:           "current is newer - patch version",
			currentVersion: "0.64.2",
			latestVersion:  "0.64.1",
			expected:       false,
		},
		{
			name:           "development version",
			currentVersion: "development",
			latestVersion:  "0.65.0",
			expected:       false,
		},
		{
			name:           "invalid latest version",
			currentVersion: "0.64.1",
			latestVersion:  "invalid",
			expected:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isNewerVersion(tc.currentVersion, tc.latestVersion)
			assert.Equal(t, tc.expected, result)
		})
	}
}
