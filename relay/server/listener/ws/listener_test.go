package ws

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
)

func TestListener_ShutdownBeforeServe(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0"}
	require.NoError(t, l.Bind())
	addr := l.listener.Addr().String()
	require.NoError(t, l.Shutdown(context.Background()))

	errChan := make(chan error, 1)
	go func() {
		errChan <- l.Serve(func(relaylistener.Conn) {})
	}()

	assert.NoError(t, waitForServeToReturn(t, errChan))
	requireTCPAddressFree(t, addr)
}

func TestListener_ShutdownStopsServe(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0"}
	require.NoError(t, l.Bind())
	addr := l.listener.Addr().String()

	errChan := make(chan error, 1)
	go func() {
		errChan <- l.Serve(func(relaylistener.Conn) {})
	}()

	// A bound socket accepts TCP connections before Serve runs, so only a served
	// HTTP response proves the accept loop is running.
	require.Eventually(t, func() bool {
		return httpGetSucceeds("http://" + addr + "/")
	}, 5*time.Second, 10*time.Millisecond, "listener did not start serving")

	require.NoError(t, l.Shutdown(context.Background()))
	assert.NoError(t, waitForServeToReturn(t, errChan))
	requireTCPAddressFree(t, addr)
}

func TestListener_Unbound(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0"}
	assert.Error(t, l.Serve(func(relaylistener.Conn) {}), "Serve must refuse an unbound listener")
	assert.NoError(t, l.Shutdown(context.Background()), "Shutdown of an unbound listener is a no-op")
}

func waitForServeToReturn(t *testing.T, errChan <-chan error) error {
	t.Helper()
	select {
	case err := <-errChan:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
		return nil
	}
}

func httpGetSucceeds(url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

func requireTCPAddressFree(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err, "tcp address %s must be released", addr)
	require.NoError(t, ln.Close())
}
