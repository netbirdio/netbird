package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "go.opentelemetry.io/otel/metric"
)

type testInstruments struct {
	requests api.Int64Counter
}

func newTestInstruments(_ context.Context, meter api.Meter) (*testInstruments, error) {
	requests, err := meter.Int64Counter("metrics_test_requests")
	if err != nil {
		return nil, err
	}
	return &testInstruments{requests: requests}, nil
}

func scrape(t *testing.T, addr, endpoint string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + endpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestRegisterAndServe(t *testing.T) {
	ctx := context.Background()
	m, err := New("metrics-test-scope")
	require.NoError(t, err)

	instruments, err := Register(ctx, m, newTestInstruments)
	require.NoError(t, err)
	instruments.requests.Add(ctx, 3)

	require.NoError(t, m.Serve(ctx, 0, ""))
	assert.Equal(t, defaultEndpoint, m.Endpoint)

	body := scrape(t, m.Server.Addr, m.Endpoint)
	assert.Contains(t, body, "metrics_test_requests")
	assert.Contains(t, body, "metrics-test-scope")

	require.NoError(t, m.Shutdown(ctx))
	_, err = net.Dial("tcp", m.Server.Addr)
	require.Error(t, err)
}

func TestServe_LeavesPreparedServerAlone(t *testing.T) {
	m, err := NewServer(0, "")
	require.NoError(t, err)

	require.NoError(t, m.Serve(context.Background(), 0, ""))
	assert.Equal(t, ":0", m.Server.Addr)
	require.NoError(t, m.Shutdown(context.Background()))
}

func TestNewServer_PreparesEndpoint(t *testing.T) {
	m, err := NewServer(0, "")
	require.NoError(t, err)

	assert.NotNil(t, m.Meter)
	assert.Equal(t, defaultEndpoint, m.Endpoint)
	assert.Equal(t, ":0", m.Server.Addr)
	require.NoError(t, m.Shutdown(context.Background()))
}
