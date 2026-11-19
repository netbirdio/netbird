package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestResponseOrigin_ErrorSource pins the admin-facing error source each
// origin maps to, so a provider failure never reads as a proxy one.
func TestResponseOrigin_ErrorSource(t *testing.T) {
	assert.Equal(t, "provider", OriginBackend.ErrorSource())
	assert.Equal(t, "proxy", OriginProxyError.ErrorSource())
	assert.Equal(t, "proxy", OriginNoRoute.ErrorSource())
	assert.Equal(t, "auth", OriginAuth.ErrorSource())
	assert.Equal(t, "policy", OriginMiddleware.ErrorSource())
}

// TestServeHTTP_ForwardedRequestIsBackendOrigin covers the regression where
// header auth stamps OriginAuth on success and a provider's own 401 was then
// reported as an auth error: once the request is handed upstream, the origin
// is the backend's.
func TestServeHTTP_ForwardedRequestIsBackendOrigin(t *testing.T) {
	rp := NewReverseProxy(statusTransport(http.StatusUnauthorized), "auto", nil, nil)
	rp.AddMapping(Mapping{
		ID:        "svc-1",
		AccountID: "acct-1",
		Host:      "llm.svc",
		Paths: map[string]*PathTarget{
			"/": {URL: &url.URL{Scheme: "http", Host: "upstream.example"}},
		},
	})

	cd := &CapturedData{}
	cd.SetOrigin(OriginAuth) // what header auth leaves behind on success
	req := httptest.NewRequest(http.MethodGet, "http://llm.svc/", nil)
	req = req.WithContext(WithCapturedData(req.Context(), cd))
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, OriginBackend, cd.GetOrigin(), "the upstream's 401 must be attributed to the backend")
}

type statusTransport int

func (s statusTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: int(s), Body: http.NoBody, Header: http.Header{}}, nil
}
