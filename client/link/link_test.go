package link

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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
