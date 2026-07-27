package appsec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/restrict"
)

// engine records what the AppSec component received and replies with a
// canned status and body.
type engine struct {
	status int
	body   string

	gotMethod string
	gotHeader http.Header
	gotBody   []byte
	gotLength int64
	requests  int
}

func (e *engine) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		e.requests++
		e.gotMethod = r.Method
		e.gotHeader = r.Header.Clone()
		e.gotBody = body
		e.gotLength = r.ContentLength

		status := e.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if e.body != "" {
			_, _ = w.Write([]byte(e.body))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, url string, cfg ...func(*Config)) *Client {
	t.Helper()
	c := Config{URL: url, APIKey: "test-key"}
	for _, fn := range cfg {
		fn(&c)
	}
	client, err := New(c)
	require.NoError(t, err)
	return client
}

func inbound(method, target string, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	r.Host = "svc.example.com"
	r.Header.Set("User-Agent", "curl/8.0")
	return r
}

func TestNew_RejectsBadConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"empty url", Config{APIKey: "k"}},
		{"empty key", Config{URL: "http://127.0.0.1:7422/"}},
		{"non http scheme", Config{URL: "tcp://127.0.0.1:7422", APIKey: "k"}},
		{"no host", Config{URL: "http:///path", APIKey: "k"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			require.Error(t, err)
		})
	}
}

func TestInspect_AllowSendsProtocolHeaders(t *testing.T) {
	eng := &engine{status: http.StatusOK, body: `{"action":"allow","http_status":200}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/admin?q=1", "")
	r.Header.Set("Cookie", "session=abc")

	res, err := client.Inspect(context.Background(), Request{
		HTTP:          r,
		ClientIP:      netip.MustParseAddr("203.0.113.7"),
		TransactionID: "req-42",
	})
	require.NoError(t, err)
	assert.Equal(t, restrict.Allow, res.Verdict, "allow action must pass the request")

	assert.Equal(t, http.MethodGet, eng.gotMethod, "a bodyless request is forwarded as GET")
	assert.Equal(t, "203.0.113.7", eng.gotHeader.Get(headerIP))
	assert.Equal(t, "/admin?q=1", eng.gotHeader.Get(headerURI), "URI header must carry path and query")
	assert.Equal(t, http.MethodGet, eng.gotHeader.Get(headerVerb))
	assert.Equal(t, "svc.example.com", eng.gotHeader.Get(headerHost))
	assert.Equal(t, "curl/8.0", eng.gotHeader.Get(headerUserAgent))
	assert.Equal(t, "11", eng.gotHeader.Get(headerHTTPVersion))
	assert.Equal(t, "req-42", eng.gotHeader.Get(headerTransactionID))
	assert.Equal(t, "test-key", eng.gotHeader.Get(headerAPIKey))
	// Client headers are what the WAF rules match on.
	assert.Equal(t, "session=abc", eng.gotHeader.Get("Cookie"))
}

func TestInspect_MapsActionsToVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    restrict.Verdict
		wantErr bool
	}{
		{"allow", http.StatusOK, `{"action":"allow"}`, restrict.Allow, false},
		{"ban", http.StatusForbidden, `{"action":"ban","http_status":403}`, restrict.DenyAppSecBan, false},
		{"captcha", http.StatusForbidden, `{"action":"captcha","http_status":403}`, restrict.DenyAppSecCaptcha, false},
		// blocked_http_code is operator-configurable, so the action decides.
		{"custom block status", http.StatusTeapot, `{"action":"ban"}`, restrict.DenyAppSecBan, false},
		{"allow on custom status", http.StatusTeapot, `{"action":"allow"}`, restrict.Allow, false},
		{"unknown action denies", http.StatusForbidden, `{"action":"something-new"}`, restrict.DenyAppSecBan, false},
		// No decodable action means no remediation was communicated, so this is
		// an engine fault, not a ban. Enforce blocks on it either way.
		{"unreadable body is unavailable", http.StatusForbidden, `not json`, restrict.DenyAppSecUnavailable, true},
		// A misdirected URL answering 404 with HTML must not read as a ban.
		{"non-appsec endpoint is unavailable", http.StatusNotFound, `<html>404</html>`, restrict.DenyAppSecUnavailable, true},
		{"bad api key is unavailable", http.StatusUnauthorized, "", restrict.DenyAppSecUnavailable, true},
		{"engine error is unavailable", http.StatusInternalServerError, "", restrict.DenyAppSecUnavailable, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := &engine{status: tt.status, body: tt.body}
			srv := eng.start(t)
			client := newClient(t, srv.URL)

			res, err := client.Inspect(context.Background(), Request{
				HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
				ClientIP: netip.MustParseAddr("203.0.113.7"),
			})
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrUnavailable), "engine-side failures must be ErrUnavailable so the caller can apply the mode")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, res.Verdict)
		})
	}
}

func TestInspect_ForwardsBodyAndRestoresIt(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	const payload = `{"user":"' OR 1=1--"}`
	r := inbound(http.MethodPost, "http://svc.example.com/login", payload)
	r.Header.Set("Content-Type", "application/json")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, eng.gotMethod, "a request with a body is forwarded as POST")
	assert.Equal(t, payload, string(eng.gotBody))
	assert.Equal(t, int64(len(payload)), eng.gotLength,
		"the engine reads exactly Content-Length bytes, so it must be accurate")

	// The backend still needs the body.
	restored, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(restored), "body must be restored for the upstream request")
}

func TestInspect_OversizeBodyFallsBackToHeaders(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL, func(c *Config) { c.MaxBodyBytes = 16 })

	payload := strings.Repeat("A", 64)
	r := inbound(http.MethodPost, "http://svc.example.com/upload", payload)

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)

	assert.Equal(t, http.MethodGet, eng.gotMethod, "an oversize body is not forwarded")
	assert.Empty(t, eng.gotBody, "a truncated prefix must never be sent: it changes the verdict")

	restored, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(restored), "the full body must still reach the upstream")
}

func TestInspect_ChunkedOversizeBodyIsReplayed(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL, func(c *Config) { c.MaxBodyBytes = 8 })

	payload := strings.Repeat("B", 40)
	r := inbound(http.MethodPost, "http://svc.example.com/upload", payload)
	// Unknown length: the cap can only be detected while reading.
	r.ContentLength = -1
	r.Header.Del("Content-Length")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)

	assert.Empty(t, eng.gotBody)
	restored, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(restored), "bytes read to detect the cap must be replayed")
}

func TestInspect_RedactsCredentialForm(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodPost, "http://svc.example.com/", "password=hunter2&next=%2Fhome")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:             r,
		ClientIP:         netip.MustParseAddr("203.0.113.7"),
		RedactBodyFields: []string{"password", "pin"},
	})
	require.NoError(t, err)

	assert.NotContains(t, string(eng.gotBody), "hunter2", "the credential must not reach the engine")
	assert.Contains(t, string(eng.gotBody), "next=%2Fhome", "the rest of the form stays inspectable")
	assert.Equal(t, 1, eng.requests)

	restored, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, "password=hunter2&next=%2Fhome", string(restored),
		"the login handler still needs to read the real form")
}

// A caller must not be able to exempt a payload from inspection by naming one
// of its fields "password": only the credential value is dropped.
func TestInspect_RedactionIsNotABodyBypass(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	const payload = "q=%27+OR+1%3D1--&password=x"
	r := inbound(http.MethodPost, "http://svc.example.com/search", payload)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:             r,
		ClientIP:         netip.MustParseAddr("203.0.113.7"),
		RedactBodyFields: []string{"password", "pin"},
	})
	require.NoError(t, err)

	forwarded := string(eng.gotBody)
	assert.Contains(t, forwarded, "OR+1%3D1", "the attack payload must still be inspected")
	assert.NotContains(t, forwarded, "password=x")
}

// A body that fails to parse carries no credential the login handler could
// read either, so it is inspected as-is rather than withheld.
func TestInspect_MalformedFormIsStillInspected(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	const payload = "q=%zz&evil=%3Cscript%3E"
	r := inbound(http.MethodPost, "http://svc.example.com/search", payload)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:             r,
		ClientIP:         netip.MustParseAddr("203.0.113.7"),
		RedactBodyFields: []string{"password", "pin"},
	})
	require.NoError(t, err)
	assert.Equal(t, payload, string(eng.gotBody))
}

func TestInspect_ForwardsNonCredentialForm(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodPost, "http://svc.example.com/search", "q=%3Cscript%3E")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:             r,
		ClientIP:         netip.MustParseAddr("203.0.113.7"),
		RedactBodyFields: []string{"password", "pin"},
	})
	require.NoError(t, err)
	assert.Equal(t, "q=%3Cscript%3E", string(eng.gotBody), "ordinary form bodies must be inspected")
}

func TestInspect_StripsSpoofedProtocolHeaders(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/", "")
	// A caller trying to make the engine see a different source address, and to
	// smuggle in its own key.
	r.Header.Set(headerIP, "10.0.0.1")
	r.Header.Set(headerAPIKey, "attacker-key")
	r.Header.Set(headerURI, "/harmless")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)

	assert.Equal(t, "203.0.113.7", eng.gotHeader.Get(headerIP), "the proxy's resolved IP must win")
	assert.Equal(t, "test-key", eng.gotHeader.Get(headerAPIKey))
	assert.Equal(t, "/", eng.gotHeader.Get(headerURI))
	assert.Len(t, eng.gotHeader.Values(headerIP), 1, "no duplicate protocol headers")
}

func TestInspect_DropsHopByHopHeaders(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/", "")
	r.Header.Set("Proxy-Authorization", "Basic zzz")
	r.Header.Set("Keep-Alive", "timeout=5")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)

	assert.Empty(t, eng.gotHeader.Get("Proxy-Authorization"))
	assert.Empty(t, eng.gotHeader.Get("Keep-Alive"))
}

func TestInspect_UpgradeRequestKeepsStreamIntact(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/ws", "")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "upgrade")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	assert.Equal(t, http.MethodGet, eng.gotMethod)
	assert.Empty(t, eng.gotBody)
	assert.Equal(t, 1, eng.requests, "upgrade requests are still inspected on headers")
}

func TestInspect_TimeoutIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client := newClient(t, srv.URL, func(c *Config) { c.Timeout = 10 * time.Millisecond })

	res, err := client.Inspect(context.Background(), Request{
		HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnavailable))
	assert.Equal(t, restrict.DenyAppSecUnavailable, res.Verdict)
}

func TestInspect_UnreachableEngineIsUnavailable(t *testing.T) {
	// Port 1 on loopback refuses connections.
	client := newClient(t, "http://127.0.0.1:1/")

	res, err := client.Inspect(context.Background(), Request{
		HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnavailable))
	assert.Equal(t, restrict.DenyAppSecUnavailable, res.Verdict)
}

func TestInspect_NilClientFailsClosed(t *testing.T) {
	var client *Client
	res, err := client.Inspect(context.Background(), Request{
		HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.Error(t, err)
	assert.Equal(t, restrict.DenyAppSecUnavailable, res.Verdict)
}

func TestInspect_NegativeCapDisablesBodyForwarding(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL, func(c *Config) { c.MaxBodyBytes = -1 })

	const payload = `{"a":1}`
	r := inbound(http.MethodPost, "http://svc.example.com/", payload)

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	assert.Empty(t, eng.gotBody)

	restored, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(restored), "an untouched body must still be forwardable")
}

func TestInspect_MapsV4MappedClientIP(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
		ClientIP: netip.MustParseAddr("::ffff:203.0.113.7"),
	})
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.7", eng.gotHeader.Get(headerIP),
		"v4-mapped addresses must be unmapped so engine allowlists and rules match")
}

// Inspection is a blocking call on every request, so the connection to the
// engine must be reused. net/http only pools a connection whose body was read
// to EOF, which a verdict path returning early would skip.
func TestInspect_ReusesConnections(t *testing.T) {
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow","http_status":200}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	client := newClient(t, srv.URL)
	for range 5 {
		res, err := client.Inspect(context.Background(), Request{
			HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
			ClientIP: netip.MustParseAddr("203.0.113.7"),
		})
		require.NoError(t, err)
		require.Equal(t, restrict.Allow, res.Verdict)
	}

	assert.Equal(t, int64(1), conns.Load(),
		"all five inspections must share one connection; a fresh handshake per request would eat the timeout budget")
}

func TestNew_ClampsOperatorValues(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantTimeout time.Duration
		wantMaxBody int64
	}{
		{"defaults", Config{}, DefaultTimeout, DefaultMaxBodyBytes},
		{"timeout below minimum", Config{Timeout: time.Microsecond}, MinTimeout, DefaultMaxBodyBytes},
		{"timeout above maximum", Config{Timeout: time.Hour}, MaxTimeout, DefaultMaxBodyBytes},
		{"body above maximum", Config{MaxBodyBytes: 1 << 30}, DefaultTimeout, MaxBodyBytesLimit},
		// A negative cap means "forward no body" and must survive clamping.
		{"negative body preserved", Config{MaxBodyBytes: -1}, DefaultTimeout, -1},
		{"in-range values kept", Config{Timeout: time.Second, MaxBodyBytes: 1 << 10}, time.Second, 1 << 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.URL = "http://127.0.0.1:7422/"
			tt.cfg.APIKey = "k"
			client, err := New(tt.cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.wantTimeout, client.http.Timeout, "inspection is in the request path, so the timeout must stay bounded")
			assert.Equal(t, tt.wantMaxBody, client.maxBodyBytes, "buffered bodies are held per in-flight request")
		})
	}
}

// A payload hidden in a pair the form parser rejects must still be inspected.
// Re-encoding from parsed values would silently drop it while a tolerant
// backend parser could still act on it.
func TestInspect_RedactionDoesNotSmuggleMalformedPairs(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	const payload = "password=hunter2&%zzSMUGGLED=attack&evil=payload"
	r := inbound(http.MethodPost, "http://svc.example.com/", payload)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:             r,
		ClientIP:         netip.MustParseAddr("203.0.113.7"),
		RedactBodyFields: []string{"password", "pin"},
	})
	require.NoError(t, err)

	forwarded := string(eng.gotBody)
	assert.Equal(t, "password=redacted&%zzSMUGGLED=attack&evil=payload", forwarded,
		"only the credential value may change; every other byte reaches the engine as sent")
	assert.NotContains(t, forwarded, "hunter2")
}

// The login handler decodes the field name before looking it up, so an escaped
// spelling is a real credential submission and must be redacted too.
func TestInspect_RedactsEscapedFieldName(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodPost, "http://svc.example.com/", "pass%77ord=hunter2")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:             r,
		ClientIP:         netip.MustParseAddr("203.0.113.7"),
		RedactBodyFields: []string{"password"},
	})
	require.NoError(t, err)

	assert.Equal(t, "pass%77ord=redacted", string(eng.gotBody), "the key is preserved as sent")
	assert.NotContains(t, string(eng.gotBody), "hunter2")
}

func TestInspect_RedactsRepeatedCredentialField(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodPost, "http://svc.example.com/", "password=one&q=keep&password=two")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:             r,
		ClientIP:         netip.MustParseAddr("203.0.113.7"),
		RedactBodyFields: []string{"password"},
	})
	require.NoError(t, err)

	assert.Equal(t, "password=redacted&q=keep&password=redacted", string(eng.gotBody))
}

// A header that does not make the forwarder treat the request as an upgrade
// must not make the inspector skip the body: the backend still receives it.
func TestInspect_FakeUpgradeHeadersDoNotSkipBody(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{"upgrade header alone", map[string]string{"Upgrade": "websocket"}},
		{"connection token alone", map[string]string{"Connection": "upgrade"}},
		{"connection keep-alive with upgrade header", map[string]string{
			"Connection": "keep-alive", "Upgrade": "websocket",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := &engine{body: `{"action":"allow"}`}
			srv := eng.start(t)
			client := newClient(t, srv.URL)

			const payload = `{"q":"' OR 1=1--"}`
			r := inbound(http.MethodPost, "http://svc.example.com/api", payload)
			r.Header.Set("Content-Type", "application/json")
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}

			res, err := client.Inspect(context.Background(), Request{
				HTTP:     r,
				ClientIP: netip.MustParseAddr("203.0.113.7"),
			})
			require.NoError(t, err)
			assert.Equal(t, payload, string(eng.gotBody),
				"the forwarder delivers this body to the backend, so it must be inspected")
			assert.Empty(t, res.BodyBypass)
		})
	}
}

// A real upgrade handshake carries no body, and is reported as a bypass so the
// coverage gap is visible.
func TestInspect_RealUpgradeIsReportedAsBypass(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodPost, "http://svc.example.com/ws", "ignored")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")

	res, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	assert.Equal(t, BypassUpgrade, res.BodyBypass)
	assert.Empty(t, eng.gotBody)
}

func TestInspect_ReportsOversizeBypass(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL, func(c *Config) { c.MaxBodyBytes = 8 })

	r := inbound(http.MethodPost, "http://svc.example.com/upload", strings.Repeat("A", 64))
	res, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	assert.Equal(t, BypassOversize, res.BodyBypass,
		"padding past the cap is attacker-controlled, so the skip must be visible")
}

// The proxy strips these three from upstream requests as credentials; the
// mirrored copy must not carry them either.
func TestInspect_RedactsCredentialsTheProxyWithholds(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/app?session_token=SECRET_JWT&q=search", "")
	r.Header.Set("Cookie", "nb_session=SECRET_SESSION; theme=dark")
	r.Header.Set("X-Api-Key", "SECRET_API_KEY")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:              r,
		ClientIP:          netip.MustParseAddr("203.0.113.7"),
		RedactHeaders:     []string{"X-Api-Key"},
		RedactCookies:     []string{"nb_session"},
		RedactQueryParams: []string{"session_token"},
	})
	require.NoError(t, err)

	assert.Equal(t, "redacted", eng.gotHeader.Get("X-Api-Key"))
	assert.Equal(t, "nb_session=redacted; theme=dark", eng.gotHeader.Get("Cookie"),
		"other cookies stay inspectable")
	assert.Equal(t, "/app?session_token=redacted&q=search", eng.gotHeader.Get(headerURI),
		"the rest of the query stays inspectable")

	forwarded := eng.gotHeader.Get("Cookie") + eng.gotHeader.Get("X-Api-Key") + eng.gotHeader.Get(headerURI)
	for _, secret := range []string{"SECRET_JWT", "SECRET_SESSION", "SECRET_API_KEY"} {
		assert.NotContains(t, forwarded, secret)
	}
}

func TestInspect_LeavesUnrelatedHeadersAndQueryIntact(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/app?q=%27+OR+1%3D1--", "")
	r.Header.Set("Cookie", "theme=dark")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:              r,
		ClientIP:          netip.MustParseAddr("203.0.113.7"),
		RedactCookies:     []string{"nb_session"},
		RedactQueryParams: []string{"session_token"},
	})
	require.NoError(t, err)
	assert.Equal(t, "theme=dark", eng.gotHeader.Get("Cookie"))
	assert.Equal(t, "/app?q=%27+OR+1%3D1--", eng.gotHeader.Get(headerURI),
		"an untouched query keeps its original encoding")
}

// r.FormValue merges the URL query into the form, so a credential passed as a
// query parameter authenticates exactly like a form post and must not be
// mirrored in the clear either.
func TestInspect_RedactsCredentialsInQuery(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/?password=hunter2&pin=1234&q=keep", "")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:              r,
		ClientIP:          netip.MustParseAddr("203.0.113.7"),
		RedactQueryParams: []string{"session_token", "password", "pin"},
	})
	require.NoError(t, err)

	uri := eng.gotHeader.Get(headerURI)
	assert.Equal(t, "/?password=redacted&pin=redacted&q=keep", uri)
	assert.NotContains(t, uri, "hunter2")
	assert.NotContains(t, uri, "1234")
}

// Inspecting a request must not change what any later layer can inspect: a
// chunked body stays chunked, so a downstream capture with a smaller cap still
// gets its truncated prefix instead of skipping on a now-known length.
func TestInspect_PreservesChunkedFraming(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	payload := strings.Repeat("A", 32)
	r := inbound(http.MethodPost, "http://svc.example.com/upload", payload)
	r.ContentLength = -1
	r.Header.Del("Content-Length")
	r.TransferEncoding = []string{"chunked"}

	_, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	assert.Equal(t, payload, string(eng.gotBody), "the body is still inspected")

	assert.Equal(t, int64(-1), r.ContentLength, "framing must stay as the client sent it")
	assert.Empty(t, r.Header.Get("Content-Length"))
	assert.Equal(t, []string{"chunked"}, r.TransferEncoding)

	restored, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, string(restored))
}

// testBudget is a minimal Budget recording reservations, so a test can assert
// both that the ceiling is honoured and that it is handed back.
type testBudget struct {
	mu        sync.Mutex
	total     int64
	used      int64
	acquires  int
	releases  int
	acquiredN []int64
}

func (b *testBudget) Acquire(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acquires++
	if b.used+n > b.total {
		return false
	}
	b.used += n
	b.acquiredN = append(b.acquiredN, n)
	return true
}

func (b *testBudget) Release(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releases++
	b.used -= n
}

func (b *testBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func TestInspect_BudgetReservesCapAndReleasesOnlyWhenCalled(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	budget := &testBudget{total: 1 << 20}
	client := newClient(t, srv.URL, func(c *Config) {
		c.MaxBodyBytes = 4096
		c.Budget = budget
	})

	r := inbound(http.MethodPost, "http://svc.example.com/", "hello")
	res, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Release, "Release must never be nil")

	// The whole cap is reserved: the reservation precedes the read, so the
	// eventual body length is not yet known.
	assert.Equal(t, []int64{4096}, budget.acquiredN, "the cap, not the body length, is reserved")
	assert.Equal(t, int64(4096), budget.inUse(),
		"the reservation must outlive Inspect: the buffered body is still r.Body for the backend")

	// The backend can still read the body while the reservation is held.
	got, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	res.Release()
	assert.Equal(t, int64(0), budget.inUse(), "Release returns the reservation")
	res.Release()
	assert.Equal(t, int64(0), budget.inUse(), "Release is idempotent")
}

func TestInspect_BudgetExhaustedSkipsBodyButStillInspects(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	// Nothing available, so the reservation always fails.
	budget := &testBudget{total: 0}
	client := newClient(t, srv.URL, func(c *Config) {
		c.MaxBodyBytes = 4096
		c.Budget = budget
	})

	r := inbound(http.MethodPost, "http://svc.example.com/", "payload")
	res, err := client.Inspect(context.Background(), Request{
		HTTP:     r,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	defer res.Release()

	assert.Equal(t, BypassBudget, res.BodyBypass, "the coverage gap must be recorded, not silent")
	assert.Equal(t, restrict.Allow, res.Verdict, "headers and URI are still inspected")
	assert.Empty(t, eng.gotBody, "no body is mirrored when the reservation fails")
	assert.Equal(t, 0, budget.releases, "a failed Acquire must not be released")

	// The body must still reach the backend untouched.
	got, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(got))
}

func TestInspect_NoBudgetConfiguredStillReleases(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	res, err := client.Inspect(context.Background(), Request{
		HTTP:     inbound(http.MethodPost, "http://svc.example.com/", "hello"),
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Release, "Release must be safe to defer even with no budget")
	res.Release()
}

// A saturated engine must fail fast rather than park a goroutine per request
// for the whole timeout, and must not be a way to switch inspection off.
func TestInspect_ShedsWhenAtCapacity(t *testing.T) {
	release := make(chan struct{})
	var inFlight atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inFlight.Add(1)
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(func() { close(release); srv.Close() })

	client := newClient(t, srv.URL, func(c *Config) {
		c.MaxConcurrent = 1
		c.Timeout = 5 * time.Second
	})

	// Occupy the only slot.
	go func() {
		_, _ = client.Inspect(context.Background(), Request{
			HTTP:     inbound(http.MethodGet, "http://svc.example.com/first", ""),
			ClientIP: netip.MustParseAddr("203.0.113.7"),
		})
	}()
	for inFlight.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	res, err := client.Inspect(context.Background(), Request{
		HTTP:     inbound(http.MethodGet, "http://svc.example.com/second", ""),
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnavailable), "shedding is an unavailability, so the per-service mode decides")
	assert.Equal(t, restrict.DenyAppSecUnavailable, res.Verdict, "a flood must not disable inspection")
	assert.Less(t, elapsed, time.Second, "shedding must not wait out the timeout")
}

// The slot is scoped to the engine call, so sequential requests reuse it.
func TestInspect_ReleasesSlotAfterCall(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL, func(c *Config) { c.MaxConcurrent = 1 })

	for range 3 {
		res, err := client.Inspect(context.Background(), Request{
			HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
			ClientIP: netip.MustParseAddr("203.0.113.7"),
		})
		require.NoError(t, err)
		require.Equal(t, restrict.Allow, res.Verdict)
	}
	assert.Equal(t, 3, eng.requests)
}

func TestNew_ClampsMaxConcurrent(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"default", 0, DefaultMaxConcurrent},
		{"above maximum", 1 << 20, MaxConcurrentLimit},
		{"in range", 8, 8},
		{"negative disables the bound", -1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(Config{URL: "http://127.0.0.1:7422/", APIKey: "k", MaxConcurrent: tt.in})
			require.NoError(t, err)
			assert.Equal(t, tt.want, cap(client.sem))
		})
	}
}

// A client may send more than one Cookie line. Reading only the first would
// mirror a session cookie carried in any later one.
func TestInspect_RedactsCookiesAcrossMultipleHeaders(t *testing.T) {
	eng := &engine{body: `{"action":"allow"}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	r := inbound(http.MethodGet, "http://svc.example.com/", "")
	r.Header.Add("Cookie", "theme=dark")
	r.Header.Add("Cookie", "nb_session=SECRET_SESSION; last=1")

	_, err := client.Inspect(context.Background(), Request{
		HTTP:          r,
		ClientIP:      netip.MustParseAddr("203.0.113.7"),
		RedactCookies: []string{"nb_session"},
	})
	require.NoError(t, err)

	got := eng.gotHeader.Values("Cookie")
	require.Len(t, got, 2, "both Cookie lines must reach the engine")
	assert.Equal(t, "theme=dark", got[0], "unrelated cookies stay inspectable")
	assert.Equal(t, "nb_session=redacted; last=1", got[1])
	for _, line := range got {
		assert.NotContains(t, line, "SECRET_SESSION")
	}
}

// A misdirected URL is the dangerous case: anything that answers 200 would
// otherwise be read as a pass, so an enforcing service would allow everything
// while reporting itself as protected.
func TestInspect_Misdirected200IsNotAPass(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"html error page", "<html><body>not found</body></html>"},
		{"empty body", ""},
		{"json without a remediation", `{"status":"ok"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := &engine{status: http.StatusOK, body: tt.body}
			srv := eng.start(t)
			client := newClient(t, srv.URL)

			res, err := client.Inspect(context.Background(), Request{
				HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
				ClientIP: netip.MustParseAddr("203.0.113.7"),
			})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrUnavailable),
				"an endpoint that is not the engine must read as unavailable, not as a pass")
			assert.Equal(t, restrict.DenyAppSecUnavailable, res.Verdict)
		})
	}
}

// A pass code other than 200 is operator-configurable (passed_http_code), so the
// action field decides rather than the status.
//
// Note the corollary: a status that forbids a body (204, 304) cannot carry a
// remediation at all, so configuring one as the pass code makes every request
// unverifiable and an enforcing service denies. Failing closed there is
// deliberate; treating a bodyless 2xx as a pass is exactly the fail-open this
// test's sibling guards against.
func TestInspect_AllowOnNonStandardPassCode(t *testing.T) {
	eng := &engine{status: http.StatusAccepted, body: `{"action":"allow","http_status":202}`}
	srv := eng.start(t)
	client := newClient(t, srv.URL)

	res, err := client.Inspect(context.Background(), Request{
		HTTP:     inbound(http.MethodGet, "http://svc.example.com/", ""),
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.NoError(t, err)
	assert.Equal(t, restrict.Allow, res.Verdict)
}
