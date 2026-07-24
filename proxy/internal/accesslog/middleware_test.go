package accesslog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// recorderClient is a minimal stub for the access-log gRPCClient interface. It
// counts SendAccessLog invocations and signals on every call so tests can
// deterministically wait for the goroutine inside Logger.log without sleeping.
type recorderClient struct {
	mu        sync.Mutex
	calls     int64
	lastEntry *proto.AccessLog
	called    chan struct{}
}

func newRecorderClient() *recorderClient {
	return &recorderClient{called: make(chan struct{}, 16)}
}

func (r *recorderClient) SendAccessLog(_ context.Context, in *proto.SendAccessLogRequest, _ ...grpc.CallOption) (*proto.SendAccessLogResponse, error) {
	r.mu.Lock()
	r.calls++
	r.lastEntry = in.GetLog()
	r.mu.Unlock()
	select {
	case r.called <- struct{}{}:
	default:
	}
	return &proto.SendAccessLogResponse{}, nil
}

func (r *recorderClient) callCount() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// newTestLogger builds a Logger backed by the supplied recorderClient. It is
// the same constructor production uses, just with a stub gRPC client — no
// mocks, no interface re-implementations.
func newTestLogger(t *testing.T, client *recorderClient) *Logger {
	t.Helper()
	logger := NewLogger(client, nil, nil)
	t.Cleanup(logger.Close)
	return logger
}

// TestMiddleware_SuppressAccessLog_SkipsLogSink asserts the suppression gate.
// When the inner handler stamps SuppressAccessLog=true on CapturedData (mirrors
// what reverseproxy does when the matched target's DisableAccessLog flag is
// set), the middleware must NOT invoke the access-log sink. Bandwidth telemetry
// (trackUsage) keeps running — it's the call to SendAccessLog that we gate.
func TestMiddleware_SuppressAccessLog_SkipsLogSink(t *testing.T) {
	client := newRecorderClient()
	l := newTestLogger(t, client)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cd := proxy.CapturedDataFromContext(r.Context())
		require.NotNil(t, cd, "middleware must inject CapturedData into the request context")
		cd.SetSuppressAccessLog(true)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(l.Middleware(inner))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/agent-network/v1/chat/completions")
	require.NoError(t, err, "GET against suppressed target must succeed")
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, "inner handler must run normally")

	// Give the goroutine fence a beat (Logger.log dispatches in a goroutine).
	// The negative assertion needs a small window: if a send is going to
	// happen, it happens promptly.
	select {
	case <-client.called:
		t.Fatalf("access-log sink must not be invoked when SuppressAccessLog=true (got %d call(s))", client.callCount())
	case <-time.After(150 * time.Millisecond):
	}

	assert.Equal(t, int64(0), client.callCount(),
		"SendAccessLog must not be called for suppressed requests")
}

// TestMiddleware_SuppressAccessLog_DefaultEmitsLog is the regression sanity:
// when nothing sets SuppressAccessLog (the universal default for every
// non-agent-network target), the middleware MUST still emit the access-log
// entry. This is the guarantee that wires-through to the EnableLogCollection
// gate without breaking anyone who isn't opted in.
func TestMiddleware_SuppressAccessLog_DefaultEmitsLog(t *testing.T) {
	client := newRecorderClient()
	l := newTestLogger(t, client)

	var innerRan atomic.Bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerRan.Store(true)
		// Intentionally DO NOT touch SuppressAccessLog — mirrors every
		// non-agent-network target.
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(l.Middleware(inner))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/service/healthz")
	require.NoError(t, err, "GET against default target must succeed")
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, "inner handler must run normally")
	require.True(t, innerRan.Load(), "inner handler must have run")

	select {
	case <-client.called:
	case <-time.After(2 * time.Second):
		t.Fatalf("SendAccessLog must be invoked for non-suppressed requests, none observed (calls=%d)", client.callCount())
	}

	assert.Equal(t, int64(1), client.callCount(),
		"non-suppressed request must produce exactly one access-log send")
}

// TestMiddleware_SuppressAccessLog_PreservesUsageTracking proves the gate is
// surgical: with SuppressAccessLog=true the access-log send is skipped, but
// the per-domain usage tracker still records the bytes transferred. This is
// the cost-monitoring guarantee called out in the gate's comment.
func TestMiddleware_SuppressAccessLog_PreservesUsageTracking(t *testing.T) {
	client := newRecorderClient()
	l := newTestLogger(t, client)

	payload := []byte("ok")
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cd := proxy.CapturedDataFromContext(r.Context())
		require.NotNil(t, cd, "middleware must inject CapturedData")
		cd.SetSuppressAccessLog(true)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})

	srv := httptest.NewServer(l.Middleware(inner))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/agent-network/v1/chat/completions")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	// Allow trackUsage to land — it runs synchronously after l.log(entry) is
	// (would have been) called.
	time.Sleep(50 * time.Millisecond)

	l.usageMux.Lock()
	usage, present := l.domainUsage[hostNoPort(srv.URL)]
	l.usageMux.Unlock()
	require.True(t, present, "domain usage must be tracked even when the access-log is suppressed")
	assert.Greater(t, usage.bytesTransferred, int64(0), "bytesTransferred must include the response payload")
	assert.Equal(t, int64(0), client.callCount(),
		"SendAccessLog must remain suppressed across the response write")
}

// hostNoPort extracts the host name from an httptest server URL. The
// middleware strips the port before keying domain usage, so the test mirrors
// that to look the entry up.
func hostNoPort(url string) string {
	// httptest URLs are always "http://127.0.0.1:PORT".
	const prefix = "http://"
	host := url[len(prefix):]
	for i := 0; i < len(host); i++ {
		if host[i] == ':' || host[i] == '/' {
			return host[:i]
		}
	}
	return host
}
