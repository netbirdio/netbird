package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/netbirdio/netbird/upload-server/types"
)

func newTestRateLimiter(t *testing.T) *middleware.APIRateLimiter {
	t.Helper()

	limiter := newRateLimiter()
	t.Cleanup(limiter.Stop)

	return limiter
}

func getUploadURL(t *testing.T, mux *http.ServeMux) int {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, types.GetURLPath+"?id=test-file", nil)
	req.Header.Set(types.ClientHeader, types.ClientHeaderValue)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	return rec.Code
}

func Test_GetUploadURLIsRateLimited(t *testing.T) {
	t.Setenv(middleware.RateLimitingBurstEnv, "2")
	t.Setenv(middleware.RateLimitingRPMEnv, "1")
	mux, _ := newLocalMux(t)

	require.Equal(t, http.StatusOK, getUploadURL(t, mux))
	require.Equal(t, http.StatusOK, getUploadURL(t, mux))
	require.Equal(t, http.StatusTooManyRequests, getUploadURL(t, mux))
}

func Test_RateLimitingIsOnByDefault(t *testing.T) {
	t.Setenv(middleware.RateLimitingEnabledEnv, "")
	t.Setenv(middleware.RateLimitingBurstEnv, "1")
	mux, _ := newLocalMux(t)

	require.Equal(t, http.StatusOK, getUploadURL(t, mux))
	require.Equal(t, http.StatusTooManyRequests, getUploadURL(t, mux))
}

func Test_RateLimitingCanBeDisabled(t *testing.T) {
	t.Setenv(middleware.RateLimitingEnabledEnv, "false")
	t.Setenv(middleware.RateLimitingBurstEnv, "1")
	mux, _ := newLocalMux(t)

	require.Equal(t, http.StatusOK, getUploadURL(t, mux))
	require.Equal(t, http.StatusOK, getUploadURL(t, mux))
}
