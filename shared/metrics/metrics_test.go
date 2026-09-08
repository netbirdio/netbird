package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsLoopbackListener(t *testing.T) {
	srv, err := NewServer("127.0.0.1:0", "")
	require.NoError(t, err)
	bound := make(chan net.Addr, 1)
	srv.BaseContext = func(listener net.Listener) context.Context {
		bound <- listener.Addr()
		return context.Background()
	}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, srv.Shutdown(ctx))
		assert.ErrorIs(t, <-done, http.ErrServerClosed, "metrics listener must stop cleanly")
	})

	var address net.Addr
	select {
	case address = <-bound:
	case <-time.After(5 * time.Second):
		t.Fatal("metrics listener did not start")
	}
	host, _, err := net.SplitHostPort(address.String())
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host, "metrics socket must bind only to loopback")

	counter, err := srv.Meter.Int64Counter("loopback_test_total")
	require.NoError(t, err)
	counter.Add(context.Background(), 1)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://" + address.String() + "/metrics")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode, "metrics endpoint must remain available")
	assert.Regexp(t, `(?m)^loopback_test_total\{[^}]*\} 1$`, string(body), "scrapes must include recorded metrics")
}
