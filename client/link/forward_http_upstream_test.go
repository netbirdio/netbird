package link

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveForward starts a forwarder for spec in front of target and returns its
// local base URL.
func serveForward(t *testing.T, spec, target string) string {
	t.Helper()

	fwd, err := ParseForward(spec)
	require.NoError(t, err)
	dialer := &overlayDialer{target: target}
	f, err := newHTTPForwarder(fwd, dialer.dial)
	require.NoError(t, err)

	go func() { _ = f.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.Close(ctx)
	})
	return "http://" + f.Addr()
}

func TestForwarderVerifiesUpstreamCertificate(t *testing.T) {
	var reached atomic.Bool
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_, _ = io.WriteString(w, "should not be served")
	}))
	defer upstream.Close()

	// The test server's certificate is signed by a CA no trust store holds, so
	// a forwarder that verifies its upstream must refuse it.
	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	base := serveForward(t, "http://127.0.0.1:0=https://grafana.internal", u.Host)

	resp, err := http.Get(base + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode, "an untrusted upstream certificate must fail the request")
	assert.Contains(t, string(body), "upstream unreachable over the overlay", "the 502 must be the forwarder's own answer")
	assert.False(t, reached.Load(), "no request may reach an upstream whose certificate was not verified")
}

func TestForwarderJoinsUpstreamBasePath(t *testing.T) {
	var gotURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.URL.RequestURI()
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	base := serveForward(t, "http://127.0.0.1:0=http://grafana.internal/api", u.Host)

	resp, err := http.Get(base + "/v1/query?q=up")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "/api/v1/query?q=up", gotURI, "the upstream's path must prefix the request path")
}

// An LLM reply streamed as server-sent events must reach the caller event by
// event. A forwarder that buffered the body would hold the first event until
// the upstream finished, which here never happens until the test has read it.
func TestForwarderStreamsEventsAsTheyArrive(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
	}))
	defer upstream.Close()
	defer close(release)

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	base := serveForward(t, "http://127.0.0.1:0=http://llm.internal", u.Host)

	resp, err := http.Get(base + "/v1/chat/completions")
	require.NoError(t, err)
	defer resp.Body.Close()

	firstLine := make(chan string, 1)
	go func(body io.Reader) {
		line, _ := bufio.NewReader(body).ReadString('\n')
		firstLine <- line
	}(resp.Body)

	select {
	case line := <-firstLine:
		assert.Equal(t, "data: first\n", line, "the first event must arrive before the stream ends")
	case <-time.After(5 * time.Second):
		t.Fatal("the first event was buffered instead of streamed")
	}
}

func TestForwarderServesConcurrentRequests(t *testing.T) {
	var served atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		_, _ = io.WriteString(w, r.URL.Query().Get("n"))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	base := serveForward(t, "http://127.0.0.1:0=http://grafana.internal", u.Host)

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := range callers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			resp, err := http.Get(fmt.Sprintf("%s/?n=%d", base, n))
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- err
				return
			}
			if got := string(body); got != fmt.Sprint(n) {
				errs <- fmt.Errorf("caller %d got the answer for %q", n, got)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err, "every concurrent caller must get its own answer")
	}
	assert.Equal(t, int64(callers), served.Load(), "every request must reach the upstream once")
}

// A publicly bound listener is reachable under names the process cannot know,
// so it does not check Host, but a page in a browser is still refused.
func TestGuardOnPublicListener(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name         string
		loopbackOnly bool
		host         string
		header       [2]string
		want         int
	}{
		{name: "public listener under its LAN name", host: "nblink.lan:8080", want: http.StatusOK},
		{name: "loopback listener under the same name", loopbackOnly: true, host: "nblink.lan:8080", want: http.StatusMisdirectedRequest},
		{name: "public listener, cross-origin fetch", host: "nblink.lan:8080", header: [2]string{"Origin", "https://attacker.example"}, want: http.StatusForbidden},
		{name: "public listener, cross-site no-cors GET", host: "nblink.lan:8080", header: [2]string{fetchSiteHeader, "cross-site"}, want: http.StatusForbidden},
		{name: "public listener, same-origin page", host: "nblink.lan:8080", header: [2]string{"Origin", "http://nblink.lan:8080"}, want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/", nil)
			if tc.header[0] != "" {
				req.Header.Set(tc.header[0], tc.header[1])
			}
			rec := httptest.NewRecorder()
			guardRebinding(next, tc.loopbackOnly).ServeHTTP(rec, req)
			assert.Equal(t, tc.want, rec.Code, "%s must be answered %d", tc.name, tc.want)
		})
	}
}

func TestBindHint(t *testing.T) {
	denied := &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EACCES)}
	err := bindHint("0.0.0.0:80", denied)
	assert.ErrorIs(t, err, os.ErrPermission, "the hint must keep the original error")
	assert.Contains(t, err.Error(), "needs a port above 1023", "a permission error must suggest an unprivileged port")

	inUse := errors.New("address already in use")
	assert.Equal(t, inUse, bindHint("127.0.0.1:8080", inUse), "other errors must pass through unchanged")
}

func TestForwardStringRoundTrips(t *testing.T) {
	fwd, err := ParseForward("http://8080=https://grafana.internal/d")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8080=https://grafana.internal/d", fwd.String(),
		"String must print the normalized spec")

	again, err := ParseForward(fwd.String())
	require.NoError(t, err)
	assert.Equal(t, fwd.Listen, again.Listen, "the printed spec must parse back to the same listener")
	assert.Equal(t, fwd.Upstream.String(), again.Upstream.String(), "and to the same upstream")
	assert.False(t, strings.Contains(fwd.String(), "  "), "the spec must not carry stray whitespace")
}
