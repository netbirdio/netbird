package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"

	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestDebugEndpointDisabledByDefault(t *testing.T) {
	s := &Server{}
	assert.False(t, s.DebugEndpointEnabled, "debug endpoint should be disabled by default")
}

func TestRouterForTLSPortUsesMainRouterForPublicPort(t *testing.T) {
	mainRouter := nbtcp.NewPortRouter(quietLifecycleLogger(), nil)
	srv := &Server{
		mainRouter:     mainRouter,
		mainPort:       8443,
		mainPublicPort: 443,
		portRouters:    make(map[uint16]*portRouter),
	}

	router, err := srv.routerForTLSPort(context.Background(), 443)
	require.NoError(t, err)
	assert.Same(t, mainRouter, router)
	assert.Empty(t, srv.portRouters, "public port must not create an unreachable internal listener")
}

func TestDebugEndpointAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty defaults to localhost",
			input:    "",
			expected: "localhost:8444",
		},
		{
			name:     "explicit localhost preserved",
			input:    "localhost:9999",
			expected: "localhost:9999",
		},
		{
			name:     "explicit address preserved",
			input:    "0.0.0.0:8444",
			expected: "0.0.0.0:8444",
		},
		{
			name:     "127.0.0.1 preserved",
			input:    "127.0.0.1:8444",
			expected: "127.0.0.1:8444",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := debugEndpointAddr(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// quietLifecycleLogger keeps lifecycle tests from spamming the test output.
func quietLifecycleLogger() *log.Logger {
	l := log.New()
	l.SetOutput(io.Discard)
	l.SetLevel(log.PanicLevel)
	return l
}

func TestStopBeforeStartIsNoOp(t *testing.T) {
	srv := New(t.Context(), Config{Logger: quietLifecycleLogger()})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := srv.Stop(ctx)
	assert.NoError(t, err, "Stop on an unstarted server must succeed without error")

	err = srv.Stop(ctx)
	assert.NoError(t, err, "Stop must remain idempotent across repeated calls")
}

func TestStartFailsWithoutManagement(t *testing.T) {
	srv := New(t.Context(), Config{
		Logger:            quietLifecycleLogger(),
		ListenAddr:        "127.0.0.1:0",
		ManagementAddress: "://broken-url",
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := srv.Start(ctx)
	require.Error(t, err, "Start must surface management dial failures")

	assert.True(t, srv.started, "started flag is set before any dial attempt so a second Start fails fast")

	err = srv.Start(ctx)
	require.Error(t, err, "second Start must reject")
	assert.Contains(t, err.Error(), "already started", "error must explain why the call was rejected")
}

func TestStopIsIdempotent(t *testing.T) {
	srv := &Server{
		Logger:    quietLifecycleLogger(),
		started:   true,
		runErrCh:  make(chan struct{}),
		runCancel: func() {},
	}
	srv.recordRunErr(errors.New("synthetic"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := srv.Stop(ctx)
	require.Error(t, err, "Stop must surface the recorded background error")
	assert.Contains(t, err.Error(), "synthetic", "error must round-trip recordRunErr's value")

	err = srv.Stop(ctx)
	require.Error(t, err, "second Stop must still report the same error")
	assert.Contains(t, err.Error(), "synthetic", "idempotent Stop must return the cached error")
}

func TestRecordRunErrPreservesFirstFailure(t *testing.T) {
	srv := &Server{
		Logger:   quietLifecycleLogger(),
		runErrCh: make(chan struct{}),
	}

	srv.recordRunErr(errors.New("first"))
	srv.recordRunErr(errors.New("second"))

	require.Error(t, srv.runErr, "first failure must be retained")
	assert.Contains(t, srv.runErr.Error(), "first", "second call must not overwrite the cached error")

	select {
	case <-srv.runErrCh:
	default:
		t.Fatal("recordRunErr must close runErrCh so waitAndStop unblocks")
	}
}

func TestStopSkipsShutdownWhenNeverStarted(t *testing.T) {
	srv := New(t.Context(), Config{Logger: quietLifecycleLogger()})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := srv.Stop(ctx)
	assert.NoError(t, err, "Stop on an unstarted server should not block on the cancelled ctx")
}

func TestRedactMappingForLog_ScrubsSensitiveFields(t *testing.T) {
	original := &proto.ProxyMapping{
		Id:        "svc-1",
		Domain:    "example.com",
		AuthToken: "super-secret-token",
		Auth: &proto.Authentication{
			SessionKey: "pubkey-not-secret",
			HeaderAuths: []*proto.HeaderAuth{
				{Header: "Authorization", HashedValue: "argon2-hash-1"},
				{Header: "X-Api-Key", HashedValue: "argon2-hash-2"},
			},
		},
		Path: []*proto.PathMapping{
			{
				Path:   "/api",
				Target: "10.0.0.1:8080",
				Options: &proto.PathTargetOptions{
					CustomHeaders: map[string]string{
						"Authorization": "Bearer upstream-token",
						"X-Tenant":      "acme",
					},
				},
			},
		},
	}

	redacted := redactMappingForLog(original)

	assert.Equal(t, "super-secret-token", original.AuthToken, "original must not be mutated")
	assert.Equal(t, "argon2-hash-1", original.Auth.HeaderAuths[0].HashedValue, "original header hash must not be mutated")
	assert.Equal(t, "Bearer upstream-token", original.Path[0].Options.CustomHeaders["Authorization"], "original custom header must not be mutated")

	assert.Equal(t, "[REDACTED]", redacted.AuthToken, "auth_token must be redacted")
	require.Len(t, redacted.Auth.HeaderAuths, 2, "header auths must be preserved in count")
	assert.Equal(t, "Authorization", redacted.Auth.HeaderAuths[0].Header, "header name must be preserved")
	assert.Equal(t, "[REDACTED]", redacted.Auth.HeaderAuths[0].HashedValue, "hashed_value must be redacted")
	assert.Equal(t, "[REDACTED]", redacted.Auth.HeaderAuths[1].HashedValue, "hashed_value must be redacted for every header auth")
	assert.Equal(t, "pubkey-not-secret", redacted.Auth.SessionKey, "session_key (public) must be preserved")

	headers := redacted.Path[0].Options.CustomHeaders
	require.Len(t, headers, 2, "custom header keys must be preserved")
	assert.Equal(t, "[REDACTED]", headers["Authorization"], "custom header values must be redacted")
	assert.Equal(t, "[REDACTED]", headers["X-Tenant"], "every custom header value must be redacted")

	assert.Equal(t, "svc-1", redacted.Id, "non-sensitive fields must round-trip")
	assert.Equal(t, "example.com", redacted.Domain, "non-sensitive fields must round-trip")
}

func TestRedactMappingForLog_HandlesEmptyOrNilFields(t *testing.T) {
	empty := &proto.ProxyMapping{Id: "svc-empty"}
	redacted := redactMappingForLog(empty)

	assert.Equal(t, "", redacted.AuthToken, "empty auth_token must remain empty (no placeholder)")
	assert.Nil(t, redacted.Auth, "nil Auth must remain nil")
	assert.Empty(t, redacted.Path, "empty Path must remain empty")
}

type statusUpdateOnlyClient struct {
	proto.ProxyServiceClient
}

func (statusUpdateOnlyClient) SendStatusUpdate(context.Context, *proto.SendStatusUpdateRequest, ...grpc.CallOption) (*proto.SendStatusUpdateResponse, error) {
	return &proto.SendStatusUpdateResponse{}, nil
}

func TestSetupTCPMappingBindsCustomListenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // test port allocated by the OS
	require.NoError(t, ln.Close())

	meter, err := proxymetrics.New(context.Background(), noop.Meter{})
	require.NoError(t, err)

	srv := &Server{
		Logger:      quietLifecycleLogger(),
		mgmtClient:  statusUpdateOnlyClient{},
		meter:       meter,
		mainPort:    8443,
		portRouters: make(map[uint16]*portRouter),
		svcPorts:    make(map[types.ServiceID][]uint16),
	}
	t.Cleanup(func() {
		srv.portMu.Lock()
		for p, pr := range srv.portRouters {
			pr.cancel()
			require.NoError(t, pr.listener.Close())
			delete(srv.portRouters, p)
		}
		srv.portMu.Unlock()
		srv.portRouterWg.Wait()
	})

	mapping := &proto.ProxyMapping{
		Type:       proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:         "svc-tcp",
		AccountId:  "acct-1",
		Domain:     "ssh.example.com",
		Mode:       "tcp",
		ListenPort: int32(port),
		Path: []*proto.PathMapping{
			{Target: "10.0.0.5:22"},
		},
	}

	require.NoError(t, srv.setupTCPMapping(context.Background(), mapping))

	srv.portMu.RLock()
	pr := srv.portRouters[port]
	ports := append([]uint16(nil), srv.svcPorts[types.ServiceID("svc-tcp")]...)
	srv.portMu.RUnlock()

	require.NotNil(t, pr, "custom TCP mapping must create a per-port router")
	assert.Equal(t, []uint16{port}, ports, "service must track the custom listen port for cleanup")

	second, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		_ = second.Close()
	}
	require.Error(t, err, "custom TCP listen port must be bound after setup")
}

func TestCustomTCPPortRouterOutlivesMappingBatchContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // test port allocated by the OS
	require.NoError(t, ln.Close())

	meter, err := proxymetrics.New(context.Background(), noop.Meter{})
	require.NoError(t, err)

	srvCtx, srvCancel := context.WithCancel(context.Background())
	t.Cleanup(srvCancel)

	srv := &Server{
		ctx:         srvCtx,
		Logger:      quietLifecycleLogger(),
		meter:       meter,
		mainPort:    8443,
		portRouters: make(map[uint16]*portRouter),
		svcPorts:    make(map[types.ServiceID][]uint16),
	}
	t.Cleanup(func() {
		srv.portMu.Lock()
		for p, pr := range srv.portRouters {
			pr.cancel()
			if err := pr.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				require.NoError(t, err)
			}
			delete(srv.portRouters, p)
		}
		srv.portMu.Unlock()
		srv.portRouterWg.Wait()
	})

	batchCtx, cancelBatch := context.WithCancel(context.Background())
	_, err = srv.getOrCreatePortRouter(batchCtx, port)
	require.NoError(t, err)

	cancelBatch()

	assert.Never(t, func() bool {
		second, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			_ = second.Close()
			return true
		}
		return false
	}, 200*time.Millisecond, 10*time.Millisecond, "custom TCP listener must outlive mapping-batch context cancellation")
}
