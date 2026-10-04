package link

import (
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freePort asks the OS for a port and releases it, so the caller can name that
// port in a spec and still be the one that binds it.
func freePort(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	require.NoError(t, l.Close())
	return port
}

// mustParse builds a Forward from a spec, failing the test if the spec is bad.
func mustParse(t *testing.T, spec string) Forward {
	t.Helper()

	fwd, err := ParseForward(spec)
	require.NoError(t, err, "spec %q must parse", spec)
	return fwd
}

// One session serves every forward it was given, which is the whole point of
// the flag repeating: a user logs in once and reaches several services.
func TestStartForwardsServesEveryForward(t *testing.T) {
	first := mustParse(t, "http://127.0.0.1:0=https://a.internal")
	second := mustParse(t, "http://127.0.0.1:0=https://b.internal")

	forwards, err := startForwards(&Config{Forwards: []Forward{first, second}}, refuseDial)
	require.NoError(t, err)
	t.Cleanup(func() { closeForwards(context.Background(), forwards) })

	require.Len(t, forwards, 2, "both forwards should be bound")
	for _, f := range forwards {
		go func() { _ = f.Serve() }()
	}

	// Each listener answers on its own address. The dialer refuses, so a 502
	// is the proof the request reached that forwarder and was routed onward,
	// rather than the port belonging to something else.
	for _, f := range forwards {
		resp, rerr := http.Get("http://" + f.Addr())
		require.NoError(t, rerr, "forward on %s must accept a request", f.Addr())
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode,
			"a forward whose dialer refuses should answer 502, not fail to serve")
	}
}

// Ports are bound before any forward is announced, so a clash on the last spec
// must not leave the earlier ones holding their sockets. The observable is the
// port: it has to be free again once startForwards has returned the error.
func TestStartForwardsReleasesEarlierPortsOnFailure(t *testing.T) {
	firstPort := freePort(t)
	clashPort := freePort(t)

	// Something else already holds the second forward's port.
	blocker, err := net.Listen("tcp", "127.0.0.1:"+clashPort)
	require.NoError(t, err)
	defer func() { _ = blocker.Close() }()

	forwards, err := startForwards(&Config{Forwards: []Forward{
		mustParse(t, "http://127.0.0.1:"+firstPort+"=https://a.internal"),
		mustParse(t, "http://127.0.0.1:"+clashPort+"=https://b.internal"),
	}}, refuseDial)

	require.Error(t, err, "a clash on the second forward must fail the whole set")
	assert.Nil(t, forwards, "no forwarder should be returned alongside the error")
	assert.Contains(t, err.Error(), clashPort, "the error should name the port that clashed")

	// The first forward's port is free again, which it would not be if its
	// listener had been left open.
	reclaimed, err := net.Listen("tcp", "127.0.0.1:"+firstPort)
	require.NoError(t, err, "the first forward's port must be released when a later bind fails")
	_ = reclaimed.Close()
}

// closeForwards releases every listener it is given, so a shutdown does not
// depend on the process exiting.
func TestCloseForwardsReleasesEveryPort(t *testing.T) {
	port := freePort(t)

	forwards, err := startForwards(&Config{Forwards: []Forward{
		mustParse(t, "http://127.0.0.1:"+port+"=https://a.internal"),
	}}, refuseDial)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	closeForwards(ctx, forwards)

	reclaimed, err := net.Listen("tcp", "127.0.0.1:"+port)
	require.NoError(t, err, "the port must be free once the forward is closed")
	_ = reclaimed.Close()
}

// captureStdout runs fn with os.Stdout redirected and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	original := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()

	fn()

	os.Stdout = original
	require.NoError(t, w.Close())
	out := <-done
	_ = r.Close()
	return out
}

// --check is what an operator runs to validate a container's configuration
// before deploying it, so it has to report the forwards it would serve and
// return without touching the network.
func TestCheckReportsTheEffectiveForwards(t *testing.T) {
	cfg := &Config{
		Check:         true,
		ManagementURL: "https://mgmt.example:443",
		Hostname:      "nblink-1",
		Forwards: []Forward{
			mustParse(t, "http://8080=https://grafana.internal"),
			mustParse(t, "http://127.0.0.1:9090=https://prometheus.internal"),
		},
	}

	var err error
	out := captureStdout(t, func() { err = Run(context.Background(), cfg) })

	require.NoError(t, err, "--check must succeed on a valid configuration")
	assert.Contains(t, out, "https://mgmt.example:443")
	assert.Contains(t, out, "nblink-1")
	assert.Contains(t, out, "forwards: 2")
	assert.Contains(t, out, "127.0.0.1:8080 -> https://grafana.internal",
		"the listen address must be reported as resolved, not as it was typed")
	assert.Contains(t, out, "127.0.0.1:9090 -> https://prometheus.internal")
	assert.Contains(t, out, "state-dir: (memory)", "an unset state dir must be named, not left blank")
}

// --check reports only whether a setup key is configured. Printing the key
// itself would put a credential on the terminal and into whatever captured it,
// which is the one thing this output must never do.
func TestCheckDoesNotPrintTheSetupKey(t *testing.T) {
	cfg := &Config{
		Check:         true,
		ManagementURL: "https://mgmt.example:443",
		SetupKey:      "EEE7B5B1-1F8C-4C9A-9E2D-0123456789AB",
		Forwards:      []Forward{mustParse(t, "http://8080=https://grafana.internal")},
	}

	var err error
	out := captureStdout(t, func() { err = Run(context.Background(), cfg) })

	require.NoError(t, err)
	assert.NotContains(t, out, cfg.SetupKey, "the setup key must never be printed")
	assert.Contains(t, out, "setup-key: true", "its presence should still be reported")
}

// namedDialer routes each overlay name to its own local server, so a test can
// tell which upstream a request actually reached.
type namedDialer struct {
	mu      sync.Mutex
	targets map[string]string
	asked   []string
}

func (d *namedDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.asked = append(d.asked, addr)
	target, ok := d.targets[addr]
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no route to %s", addr)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, target)
}

func namedUpstream(t *testing.T, name string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Host
}

// Every forward shares the one overlay dialer and asks it for its own
// upstream, so two specs reach two different services rather than the same one.
func TestStartForwardsRouteEachToItsOwnUpstream(t *testing.T) {
	dialer := &namedDialer{targets: map[string]string{
		"grafana.internal:80":    namedUpstream(t, "grafana"),
		"prometheus.internal:80": namedUpstream(t, "prometheus"),
	}}

	cfg := &Config{}
	for _, spec := range []string{
		"http://127.0.0.1:0=http://grafana.internal",
		"http://127.0.0.1:0=http://prometheus.internal",
	} {
		fwd, err := ParseForward(spec)
		require.NoError(t, err)
		cfg.Forwards = append(cfg.Forwards, fwd)
	}

	forwards, err := startForwards(cfg, dialer.dial)
	require.NoError(t, err)
	require.Len(t, forwards, 2, "every configured forward must be started")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		closeForwards(ctx, forwards)
	})
	for _, f := range forwards {
		go func(f *httpForwarder) { _ = f.Serve() }(f)
	}
	require.NotEqual(t, forwards[0].Addr(), forwards[1].Addr(), "each forward must bind its own port")

	for i, want := range []string{"grafana", "prometheus"} {
		resp, err := http.Get("http://" + forwards[i].Addr() + "/")
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "forward %d must be served", i)
		assert.Equal(t, want, string(body), "forward %d must reach its own upstream", i)
	}

	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	assert.ElementsMatch(t, []string{"grafana.internal:80", "prometheus.internal:80"}, dialer.asked,
		"both forwards must share the one overlay dialer, each asking for its own name")
}

func TestPrintEffectiveConfig(t *testing.T) {
	const key = "11111111-2222-3333-4444-555555555555"
	cfg := &Config{ManagementURL: "https://management.invalid", SetupKey: key}
	for _, spec := range []string{
		"http://8080=https://grafana.internal",
		"http://127.0.0.1:0=http://prometheus.internal:9090/api",
	} {
		fwd, err := ParseForward(spec)
		require.NoError(t, err)
		cfg.Forwards = append(cfg.Forwards, fwd)
	}

	var out strings.Builder
	require.NoError(t, printEffectiveConfig(&out, cfg))

	assert.Equal(t, "management-url: https://management.invalid\n"+
		"state-dir: (memory)\n"+
		"hostname: (host default)\n"+
		"setup-key: true\n"+
		"forwards: 2\n"+
		"  127.0.0.1:8080 -> https://grafana.internal\n"+
		"  127.0.0.1:0 -> http://prometheus.internal:9090/api\n",
		out.String(), "the check must print the effective configuration")
	assert.NotContains(t, out.String(), key, "the check must report a key is set, never the key")
}

// The embedded client's management dial ignores cancellation, so a start that
// does the same must not hold a signal until it gives up on its own.
func TestStartSessionReturnsWhenInterrupted(t *testing.T) {
	release := make(chan error)
	start := func(context.Context) error { return <-release }
	var stopped atomic.Bool

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- startSession(ctx, start, func() { stopped.Store(true) }) }()

	cancel()
	select {
	case err := <-result:
		assert.ErrorIs(t, err, context.Canceled, "an interrupted start must report the cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("startSession waited for a start that ignores cancellation")
	}

	// The start completes after the caller gave up. Its session must not be
	// left running.
	release <- nil
	assert.Eventually(t, stopped.Load, 2*time.Second, 10*time.Millisecond,
		"a session that came up after the interrupt must be stopped")
}

func TestStartSessionReportsStartFailure(t *testing.T) {
	failure := errors.New("login: permission denied")
	err := startSession(context.Background(), func(context.Context) error { return failure }, func() {
		t.Error("a session that never started must not be stopped")
	})
	assert.ErrorIs(t, err, failure, "the start error must be returned")
	assert.Contains(t, err.Error(), "start client", "the error must say which step failed")
}

func TestStartSessionBoundsTheStart(t *testing.T) {
	var deadline time.Time
	err := startSession(context.Background(), func(ctx context.Context) error {
		deadline, _ = ctx.Deadline()
		return nil
	}, func() {})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(startTimeout), deadline, 5*time.Second,
		"the start must run under startTimeout")
}

func TestInterruptedOr(t *testing.T) {
	failure := errors.New("wait for login: context canceled")

	ctx, cancel := context.WithCancel(context.Background())
	assert.Equal(t, failure, interruptedOr(ctx, failure), "an error while running must be returned")
	cancel()
	assert.NoError(t, interruptedOr(ctx, failure), "an error caused by a signal must be a clean exit")
}

func TestWaitForShutdownReturnsWhenAForwardStops(t *testing.T) {
	fwd, err := ParseForward("http://127.0.0.1:0=http://grafana.internal")
	require.NoError(t, err)
	f, err := newHTTPForwarder(fwd, refuseDial)
	require.NoError(t, err)

	// Closing the raw listener under a serving forwarder is how a forward
	// dies on its own, and the process must not keep running without it.
	result := make(chan error, 1)
	go func() { result <- waitForShutdown(context.Background(), []*httpForwarder{f}) }()
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, f.listener.Close())

	select {
	case err := <-result:
		assert.Error(t, err, "a forward that stopped serving must end the run with an error")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForShutdown kept running after its only forward stopped")
	}
	_ = f.Close(context.Background())
}

func TestWaitForShutdownReturnsWhenContextEnds(t *testing.T) {
	fwd, err := ParseForward("http://127.0.0.1:0=http://grafana.internal")
	require.NoError(t, err)
	f, err := newHTTPForwarder(fwd, refuseDial)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close(context.Background()) })

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- waitForShutdown(ctx, []*httpForwarder{f}) }()
	cancel()

	select {
	case err := <-result:
		assert.NoError(t, err, "a cancelled context is a clean shutdown")
	case <-time.After(5 * time.Second):
		t.Fatal("waitForShutdown ignored the cancelled context")
	}
}

func TestRunCheckReturnsWithoutConnecting(t *testing.T) {
	fwd, err := ParseForward("http://127.0.0.1:0=https://grafana.internal")
	require.NoError(t, err)
	// An unroutable management URL and no setup key: a run that tried to log
	// in would block on the browser flow or fail to connect, not return nil.
	cfg := &Config{ManagementURL: "https://management.invalid", Check: true, Forwards: []Forward{fwd}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assert.NoError(t, Run(ctx, cfg), "a check must return before any network access")
	assert.NoError(t, ctx.Err(), "a check must return immediately")
}
