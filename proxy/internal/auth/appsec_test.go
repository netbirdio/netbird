package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/appsec"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// appsecEngine is a stub AppSec component returning a fixed remediation.
func appsecEngine(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// serveWithAppSec runs a request through the middleware for a domain configured
// with the given AppSec mode, returning the response and the captured metadata.
func serveWithAppSec(t *testing.T, mode restrict.AppSecMode, client *appsec.Client, r *http.Request) (*httptest.ResponseRecorder, map[string]string, bool) {
	t.Helper()

	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	mw.SetAppSec(client)
	require.NoError(t, mw.AddDomain("svc.example.com", DomainSettings{
		AccountID:  types.AccountID("acct-1"),
		ServiceID:  types.ServiceID("svc-1"),
		AppSecMode: mode,
	}))

	reached := false
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	cd := proxy.NewCapturedData("req-1")
	r = r.WithContext(proxy.WithCapturedData(r.Context(), cd))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	return rec, cd.GetMetadata(), reached
}

func appsecRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://svc.example.com/?x=/etc/passwd", nil)
	r.Host = "svc.example.com"
	r.RemoteAddr = "203.0.113.7:44444"
	return r
}

func TestCheckAppSec_EnforceBlocksBannedRequest(t *testing.T) {
	srv := appsecEngine(t, http.StatusForbidden, `{"action":"ban","http_status":403}`)
	client, err := appsec.New(appsec.Config{URL: srv.URL, APIKey: "k"})
	require.NoError(t, err)

	rec, meta, reached := serveWithAppSec(t, restrict.AppSecEnforce, client, appsecRequest())

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, reached, "a banned request must not reach the backend")
	assert.Equal(t, "appsec_ban", meta["appsec_verdict"])
	assert.NotContains(t, meta, "appsec_mode", "enforce is the default, only observe is annotated")
}

func TestCheckAppSec_ObserveAllowsAndRecordsVerdict(t *testing.T) {
	srv := appsecEngine(t, http.StatusForbidden, `{"action":"ban","http_status":403}`)
	client, err := appsec.New(appsec.Config{URL: srv.URL, APIKey: "k"})
	require.NoError(t, err)

	rec, meta, reached := serveWithAppSec(t, restrict.AppSecObserve, client, appsecRequest())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached, "observe mode must not block")
	assert.Equal(t, "appsec_ban", meta["appsec_verdict"])
	assert.Equal(t, "observe", meta["appsec_mode"])
}

func TestCheckAppSec_AllowedRequestPasses(t *testing.T) {
	srv := appsecEngine(t, http.StatusOK, `{"action":"allow","http_status":200}`)
	client, err := appsec.New(appsec.Config{URL: srv.URL, APIKey: "k"})
	require.NoError(t, err)

	rec, meta, reached := serveWithAppSec(t, restrict.AppSecEnforce, client, appsecRequest())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
	assert.NotContains(t, meta, "appsec_verdict", "a clean request records no verdict")
}

func TestCheckAppSec_OffSkipsInspection(t *testing.T) {
	// An engine that would ban everything; the mode must keep us away from it.
	srv := appsecEngine(t, http.StatusForbidden, `{"action":"ban"}`)
	client, err := appsec.New(appsec.Config{URL: srv.URL, APIKey: "k"})
	require.NoError(t, err)

	rec, meta, reached := serveWithAppSec(t, restrict.AppSecOff, client, appsecRequest())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
	assert.Empty(t, meta)
}

func TestCheckAppSec_EnforceFailsClosedWithoutClient(t *testing.T) {
	rec, meta, reached := serveWithAppSec(t, restrict.AppSecEnforce, nil, appsecRequest())

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"enforce with no configured endpoint must deny rather than pass traffic uninspected")
	assert.False(t, reached)
	assert.Equal(t, "appsec_unavailable", meta["appsec_verdict"])
}

func TestCheckAppSec_ObserveAllowsWithoutClient(t *testing.T) {
	rec, meta, reached := serveWithAppSec(t, restrict.AppSecObserve, nil, appsecRequest())

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
	assert.Equal(t, "appsec_unavailable", meta["appsec_verdict"])
	assert.Equal(t, "observe", meta["appsec_mode"])
}

func TestCheckAppSec_EnforceFailsClosedWhenEngineUnreachable(t *testing.T) {
	client, err := appsec.New(appsec.Config{URL: "http://127.0.0.1:1/", APIKey: "k"})
	require.NoError(t, err)

	rec, meta, reached := serveWithAppSec(t, restrict.AppSecEnforce, client, appsecRequest())

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, reached)
	assert.Equal(t, "appsec_unavailable", meta["appsec_verdict"])
}

func TestCheckAppSec_InspectsOverlayTraffic(t *testing.T) {
	srv := appsecEngine(t, http.StatusForbidden, `{"action":"ban"}`)
	client, err := appsec.New(appsec.Config{URL: srv.URL, APIKey: "k"})
	require.NoError(t, err)

	// Requests arriving over the WireGuard overlay skip the geo and IP-reputation
	// checks, but request content is just as inspectable.
	r := appsecRequest()
	r = r.WithContext(types.WithOverlayOrigin(r.Context()))

	rec, meta, reached := serveWithAppSec(t, restrict.AppSecEnforce, client, r)

	assert.Equal(t, http.StatusForbidden, rec.Code, "overlay traffic must still be inspected")
	assert.False(t, reached)
	assert.Equal(t, "appsec_ban", meta["appsec_verdict"])
}

func TestCheckAppSec_UnresolvableClientIPFailsClosed(t *testing.T) {
	srv := appsecEngine(t, http.StatusOK, `{"action":"allow"}`)
	client, err := appsec.New(appsec.Config{URL: srv.URL, APIKey: "k"})
	require.NoError(t, err)

	r := appsecRequest()
	r.RemoteAddr = "not-an-address"

	rec, meta, reached := serveWithAppSec(t, restrict.AppSecEnforce, client, r)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"the engine requires a client address; a request we cannot attribute must not pass")
	assert.False(t, reached)
	assert.Equal(t, "appsec_unavailable", meta["appsec_verdict"])
}

// The redaction sets are resolved from the domain's schemes at registration, so
// what AppSec withholds cannot drift from what those schemes actually accept.
func TestAddDomain_ResolvesRedactionSetsFromSchemes(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain("svc.example.com", DomainSettings{
		Schemes: []Scheme{
			NewPassword(nil, "svc-1", "acct-1"),
			NewHeader("X-Api-Key", nil),
		},
		SessionPublicKey:  base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		SessionExpiration: time.Hour,
		AppSecMode:        restrict.AppSecEnforce,
	}))

	mw.domainsMux.RLock()
	config := mw.domains["svc.example.com"]
	mw.domainsMux.RUnlock()

	assert.Equal(t, []string{"password"}, config.redactBodyFields)
	assert.Equal(t, []string{"X-Api-Key"}, config.redactHeaders)
	// r.FormValue merges the query into the form, so a credential passed there
	// authenticates and must be redacted alongside the OIDC session token.
	assert.Equal(t, []string{"session_token", "password"}, config.redactQueryParams)
}

// countingBudget records reservations so a test can observe when the
// middleware hands them back.
type countingBudget struct {
	mu        sync.Mutex
	total     int64
	used      int64
	maxAtOnce int64
}

func (b *countingBudget) Acquire(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.total {
		return false
	}
	b.used += n
	if b.used > b.maxAtOnce {
		b.maxAtOnce = b.used
	}
	return true
}

func (b *countingBudget) Release(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
}

func (b *countingBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// The buffered body stays alive as r.Body until the backend has read it, so
// Protect must hold the reservation for the whole request and return it only
// once the handler chain has unwound. Releasing inside Inspect would let the
// budget admit buffering that is still resident.
func TestProtect_AppSecBudgetHeldForRequestAndReleasedAfter(t *testing.T) {
	srv := appsecEngine(t, http.StatusOK, `{"action":"allow"}`)
	budget := &countingBudget{total: 1 << 20}
	client, err := appsec.New(appsec.Config{
		URL:          srv.URL,
		APIKey:       "k",
		MaxBodyBytes: 4096,
		Budget:       budget,
	})
	require.NoError(t, err)

	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	mw.SetAppSec(client)
	require.NoError(t, mw.AddDomain("svc.example.com", DomainSettings{
		AccountID:  types.AccountID("acct-1"),
		ServiceID:  types.ServiceID("svc-1"),
		AppSecMode: restrict.AppSecEnforce,
	}))

	var inHandler int64
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The backend reads the buffered body here, so the reservation must
		// still be held at this point.
		inHandler = budget.inUse()
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodPost, "http://svc.example.com/", strings.NewReader("payload"))
	r.Host = "svc.example.com"
	cd := proxy.NewCapturedData("req-1")
	r = r.WithContext(proxy.WithCapturedData(r.Context(), cd))

	handler.ServeHTTP(httptest.NewRecorder(), r)

	assert.Equal(t, int64(4096), inHandler, "the reservation must be held while the backend reads the body")
	assert.Equal(t, int64(0), budget.inUse(), "Protect must release the reservation once the request is served")
}

// A denied request never reaches the backend, but Protect still has to hand the
// reservation back or the pool leaks one cap per blocked request.
func TestProtect_AppSecBudgetReleasedOnDeny(t *testing.T) {
	srv := appsecEngine(t, http.StatusForbidden, `{"action":"ban"}`)
	budget := &countingBudget{total: 1 << 20}
	client, err := appsec.New(appsec.Config{
		URL:          srv.URL,
		APIKey:       "k",
		MaxBodyBytes: 4096,
		Budget:       budget,
	})
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "http://svc.example.com/", strings.NewReader("payload"))
	r.Host = "svc.example.com"
	rec, _, reached := serveWithAppSec(t, restrict.AppSecEnforce, client, r)

	assert.False(t, reached, "a banned request must not reach the backend")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, int64(0), budget.inUse(), "a blocked request must not leak its reservation")
}
