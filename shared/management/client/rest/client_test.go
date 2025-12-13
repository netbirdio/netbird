//go:build integration

package rest_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
