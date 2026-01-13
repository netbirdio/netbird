//go:build integration

package rest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/http/testing/testing_tools/channel"
	"github.com/netbirdio/netbird/shared/management/client/rest"
)

func withMockClient(callback func(*rest.Client, *http.ServeMux)) {
	mux := &http.ServeMux{}
	server := httptest.NewServer(mux)
	defer server.Close()
	c := rest.New(server.URL, "ABC")
	callback(c, mux)
}

func ptr[T any, PT *T](x T) PT {
	return &x
}

func withBlackBoxServer(t *testing.T, callback func(*rest.Client)) {
	t.Helper()
	handler, _, _ := channel.BuildApiBlackBoxWithDBState(t, "../../../../management/server/testdata/store.sql", nil, false)
	server := httptest.NewServer(handler)
	defer server.Close()
	c := rest.New(server.URL, "nbp_apTmlmUXHSC4PKmHwtIZNaGr8eqcVI2gMURp")
	callback(c)
}

func TestClient_UserAgent_Set(t *testing.T) {
	expectedUserAgent := "TestApp/1.2.3"
	mux := &http.ServeMux{}
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/api/accounts", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectedUserAgent, r.Header.Get("User-Agent"))
		w.WriteHeader(200)
		_, err := w.Write([]byte("[]"))
		require.NoError(t, err)
	})

	c := rest.NewWithOptions(
		rest.WithManagementURL(server.URL),
		rest.WithPAT("test-token"),
		rest.WithUserAgent(expectedUserAgent),
	)

	_, err := c.Accounts.List(context.Background())
	require.NoError(t, err)
}

func TestClient_UserAgent_NotSet(t *testing.T) {
	mux := &http.ServeMux{}
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/api/accounts", func(w http.ResponseWriter, r *http.Request) {
		// When no custom user agent is set, Go's default HTTP client will set one
		// We just verify that the header exists (it will be Go's default)
		userAgent := r.Header.Get("User-Agent")
		assert.NotEmpty(t, userAgent)
		w.WriteHeader(200)
		_, err := w.Write([]byte("[]"))
		require.NoError(t, err)
	})

	c := rest.NewWithOptions(
		rest.WithManagementURL(server.URL),
		rest.WithPAT("test-token"),
	)

	_, err := c.Accounts.List(context.Background())
	require.NoError(t, err)
}
