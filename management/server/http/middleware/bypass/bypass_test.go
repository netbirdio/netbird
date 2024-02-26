package bypass_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/http/middleware/bypass"
)

func TestGetList(t *testing.T) {
	bypassPaths := []string{"/path1", "/path2", "/path3"}

	for _, path := range bypassPaths {
		err := bypass.AddBypassPath(path)
		require.NoError(t, err, "Adding bypass path should not fail")
	}

	list := bypass.GetList()

	assert.ElementsMatch(t, bypassPaths, list, "Bypass path list did not match expected paths")
}

func TestAuthBypass(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		pathToAdd      string
		pathToRemove   string
		testPath       string
		expectBypass   bool
		expectHTTPCode int
	}{
		{
			name:           "Path added to bypass",
			pathToAdd:      "/bypass",
			testPath:       "/bypass",
			expectBypass:   true,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Wildcard path added to bypass",
			pathToAdd:      "/bypass/*",
			testPath:       "/bypass/extra",
			expectBypass:   true,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Path not added to bypass",
			testPath:       "/no-bypass",
			expectBypass:   false,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Path removed from bypass",
			pathToAdd:      "/remove-bypass",
			pathToRemove:   "/remove-bypass",
			testPath:       "/remove-bypass",
			expectBypass:   false,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Exact path matches bypass",
			pathToAdd:      "/webhook",
			testPath:       "/webhook",
			expectBypass:   true,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Subpath does not match bypass",
			pathToAdd:      "/webhook",
			testPath:       "/webhook/extra",
			expectBypass:   false,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Wildcard subpath does not match bypass",
			pathToAdd:      "/webhook/*",
			testPath:       "/webhook/extra/path",
			expectBypass:   false,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Similar path does not match bypass",
			pathToAdd:      "/webhook",
			testPath:       "/webhooking",
			expectBypass:   false,
			expectHTTPCode: http.StatusOK,
		},
		{
			name:           "Prefix path does not match bypass",
			pathToAdd:      "/webhook",
			testPath:       "/web",
			expectBypass:   false,
			expectHTTPCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pathToAdd != "" {
				err := bypass.AddBypassPath(tc.pathToAdd)
				require.NoError(t, err, "Adding bypass path should not fail")
				defer bypass.RemovePath(tc.pathToAdd)
			}

			if tc.pathToRemove != "" {
				bypass.RemovePath(tc.pathToRemove)
			}

			request, err := http.NewRequest("GET", tc.testPath, nil)
			require.NoError(t, err, "Creating request should not fail")

			recorder := httptest.NewRecorder()

			bypassed := bypass.ShouldBypass(tc.testPath, dummyHandler, recorder, request)

			assert.Equal(t, tc.expectBypass, bypassed, "Bypass check did not match expectation")

			if tc.expectBypass {
				assert.Equal(t, tc.expectHTTPCode, recorder.Code, "HTTP status code did not match expectation for bypassed path")
			}
		})
	}
}
