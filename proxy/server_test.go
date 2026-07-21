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
	goproto "google.golang.org/protobuf/proto"

	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/types"
	udprelay "github.com/netbirdio/netbird/proxy/internal/udp"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestDebugEndpointDisabledByDefault(t *testing.T) {
	s := &Server{}
	assert.False(t, s.DebugEndpointEnabled, "debug endpoint should be disabled by default")
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

func TestValidateWirePortMapping(t *testing.T) {
	tests := []struct {
		name    string
		mapping *proto.ServicePortMapping
		wantErr string
	}{
		{
			name: "translated range",
			mapping: &proto.ServicePortMapping{
				Protocol: "udp", ListenPortStart: 5000, ListenPortEnd: 5030,
				TargetPortStart: 6000, TargetPortEnd: 6030,
			},
		},
		{name: "nil", wantErr: "must not be nil"},
		{
			name: "zero",
			mapping: &proto.ServicePortMapping{
				Protocol: "tcp", ListenPortStart: 0, ListenPortEnd: 1,
				TargetPortStart: 1, TargetPortEnd: 2,
			},
			wantErr: "between 1 and 65535",
		},
		{
			name: "above uint16",
			mapping: &proto.ServicePortMapping{
				Protocol: "tcp", ListenPortStart: 65536, ListenPortEnd: 65536,
				TargetPortStart: 1, TargetPortEnd: 1,
			},
			wantErr: "between 1 and 65535",
		},
		{
			name: "listener reversed",
			mapping: &proto.ServicePortMapping{
				Protocol: "tcp", ListenPortStart: 11, ListenPortEnd: 10,
				TargetPortStart: 20, TargetPortEnd: 21,
			},
			wantErr: "listener range is reversed",
		},
		{
			name: "target reversed",
			mapping: &proto.ServicePortMapping{
				Protocol: "tcp", ListenPortStart: 10, ListenPortEnd: 11,
				TargetPortStart: 21, TargetPortEnd: 20,
			},
			wantErr: "target range is reversed",
		},
		{
			name: "range size mismatch",
			mapping: &proto.ServicePortMapping{
				Protocol: "tcp", ListenPortStart: 10, ListenPortEnd: 12,
				TargetPortStart: 20, TargetPortEnd: 21,
			},
			wantErr: "same number of ports",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listenStart, listenEnd, targetStart, err := validateWirePortMapping(2, tt.mapping)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, uint16(5000), listenStart)
			assert.Equal(t, uint16(5030), listenEnd)
			assert.Equal(t, uint16(6000), targetStart)
		})
	}
}

func TestSinglePortMappingTranslatesTargetWithoutMutatingParent(t *testing.T) {
	parent := &proto.ProxyMapping{
		Id: "svc-multi", AccountId: "account-1", Domain: "game.example.test",
		Mode: "tcp", ListenPort: 8080,
		Path: []*proto.PathMapping{{Target: "[fd00::10]:18080"}},
		PortMappings: []*proto.ServicePortMapping{{
			Protocol: "udp", ListenPortStart: 9001, ListenPortEnd: 9003,
			TargetPortStart: 19001, TargetPortEnd: 19003,
		}},
	}

	child := singlePortMapping(parent, "udp", "fd00::10", 9002, 19002)
	assert.Equal(t, "udp", child.Mode)
	assert.Equal(t, int32(9002), child.ListenPort)
	require.Len(t, child.Path, 1)
	assert.Equal(t, "[fd00::10]:19002", child.Path[0].Target)
	assert.Nil(t, child.PortMappings)

	assert.Equal(t, "tcp", parent.Mode)
	assert.Equal(t, int32(8080), parent.ListenPort)
	assert.Equal(t, "[fd00::10]:18080", parent.Path[0].Target)
	require.Len(t, parent.PortMappings, 1)
}

func TestServiceKeyForMappingIsStableAcrossL4Representations(t *testing.T) {
	srv := &Server{}
	want := roundtrip.L4ServiceKey("svc-1")

	for _, mapping := range []*proto.ProxyMapping{
		{Id: "svc-1", Domain: "tls.example.test", Mode: "tls", ListenPort: 443},
		{Id: "svc-1", Domain: "tls.example.test", Mode: "tcp", ListenPort: 443},
		{
			Id: "svc-1", Domain: "tls.example.test", Mode: "tls", ListenPort: 443,
			PortMappings: []*proto.ServicePortMapping{
				{Protocol: "tls", ListenPortStart: 443, ListenPortEnd: 443, TargetPortStart: 443, TargetPortEnd: 443},
				{Protocol: "udp", ListenPortStart: 9001, ListenPortEnd: 9001, TargetPortStart: 9001, TargetPortEnd: 9001},
			},
		},
	} {
		assert.Equal(t, want, srv.serviceKeyForMapping(mapping))
	}

	assert.Equal(t, roundtrip.DomainServiceKey("app.example.test"), srv.serviceKeyForMapping(&proto.ProxyMapping{
		Id: "svc-http", Domain: "app.example.test", Mode: "http",
	}))
}

func TestSetupPortMappingsCreatesEveryTCPListener(t *testing.T) {
	first := reserveTCPPort(t)
	second := reserveTCPPort(t)
	for second == first {
		second = reserveTCPPort(t)
	}

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
		for port, router := range srv.portRouters {
			router.cancel()
			if err := router.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				require.NoError(t, err)
			}
			delete(srv.portRouters, port)
		}
		srv.portMu.Unlock()
		srv.portRouterWg.Wait()
	})

	mapping := &proto.ProxyMapping{
		Id: "svc-multi", AccountId: "account-1", Domain: "game.example.test",
		Mode: "tcp", ListenPort: int32(first),
		Path: []*proto.PathMapping{{Target: "100.64.0.10:8080"}},
		PortMappings: []*proto.ServicePortMapping{
			{Protocol: "tcp", ListenPortStart: uint32(first), ListenPortEnd: uint32(first), TargetPortStart: 18080, TargetPortEnd: 18080},
			{Protocol: "tcp", ListenPortStart: uint32(second), ListenPortEnd: uint32(second), TargetPortStart: 19000, TargetPortEnd: 19000},
		},
	}
	require.NoError(t, srv.setupPortMappings(context.Background(), mapping))

	srv.portMu.RLock()
	tracked := append([]uint16(nil), srv.svcPorts[types.ServiceID(mapping.Id)]...)
	_, firstExists := srv.portRouters[first]
	_, secondExists := srv.portRouters[second]
	srv.portMu.RUnlock()
	assert.ElementsMatch(t, []uint16{first, second}, tracked)
	assert.True(t, firstExists)
	assert.True(t, secondExists)
}

func TestSetupPortMappingsAllowsEqualTCPUDPPortAndMultipleUDPRelays(t *testing.T) {
	sharedPort := reserveTCPPort(t)
	secondUDPPort := reserveUDPPort(t)
	for secondUDPPort == sharedPort {
		secondUDPPort = reserveUDPPort(t)
	}

	meter, err := proxymetrics.New(context.Background(), noop.Meter{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &Server{
		ctx:         ctx,
		Logger:      quietLifecycleLogger(),
		mgmtClient:  statusUpdateOnlyClient{},
		meter:       meter,
		mainPort:    8443,
		portRouters: make(map[uint16]*portRouter),
		svcPorts:    make(map[types.ServiceID][]uint16),
		udpRelays:   make(map[udpRelayKey]*udprelay.Relay),
		dialResolver: func(types.AccountID) (types.DialContextFunc, error) {
			return (&net.Dialer{}).DialContext, nil
		},
	}
	t.Cleanup(func() {
		srv.removeUDPRelays("svc-mixed")
		srv.udpRelayWg.Wait()
		srv.portMu.Lock()
		for port, router := range srv.portRouters {
			router.cancel()
			if err := router.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				require.NoError(t, err)
			}
			delete(srv.portRouters, port)
		}
		srv.portMu.Unlock()
		srv.portRouterWg.Wait()
	})

	mapping := &proto.ProxyMapping{
		Id: "svc-mixed", AccountId: "account-1", Domain: "game.example.test",
		Mode: "tcp", ListenPort: int32(sharedPort),
		Path: []*proto.PathMapping{{Target: "127.0.0.1:8080"}},
		PortMappings: []*proto.ServicePortMapping{
			{Protocol: "tcp", ListenPortStart: uint32(sharedPort), ListenPortEnd: uint32(sharedPort), TargetPortStart: 8080, TargetPortEnd: 8080},
			{Protocol: "tls", ListenPortStart: uint32(sharedPort), ListenPortEnd: uint32(sharedPort), TargetPortStart: 9443, TargetPortEnd: 9443},
			{Protocol: "udp", ListenPortStart: uint32(sharedPort), ListenPortEnd: uint32(sharedPort), TargetPortStart: 9001, TargetPortEnd: 9001},
			{Protocol: "udp", ListenPortStart: uint32(secondUDPPort), ListenPortEnd: uint32(secondUDPPort), TargetPortStart: 9002, TargetPortEnd: 9002},
		},
	}
	require.NoError(t, srv.setupPortMappings(context.Background(), mapping))

	srv.portMu.RLock()
	_, tcpExists := srv.portRouters[sharedPort]
	srv.portMu.RUnlock()
	srv.udpMu.Lock()
	_, sharedUDPExists := srv.udpRelays[udpRelayKey{serviceID: "svc-mixed", port: sharedPort}]
	_, secondUDPExists := srv.udpRelays[udpRelayKey{serviceID: "svc-mixed", port: secondUDPPort}]
	srv.udpMu.Unlock()
	assert.True(t, tcpExists, "TCP listener must bind the shared numeric port")
	assert.True(t, sharedUDPExists, "UDP relay must coexist on the shared numeric port")
	assert.True(t, secondUDPExists, "one service must retain more than one UDP relay")
}

func TestModifyPortMappingsKeepsEmbeddedPeerState(t *testing.T) {
	port := reserveTCPPort(t)
	meter, err := proxymetrics.New(context.Background(), noop.Meter{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := quietLifecycleLogger()
	srv := &Server{
		ctx:              ctx,
		Logger:           logger,
		mgmtClient:       statusUpdateOnlyClient{},
		meter:            meter,
		mainPort:         8443,
		portRouters:      make(map[uint16]*portRouter),
		svcPorts:         make(map[types.ServiceID][]uint16),
		udpRelays:        make(map[udpRelayKey]*udprelay.Relay),
		lastMappings:     make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
		netbird:          roundtrip.NewNetBird(ctx, "proxy-1", "proxy.example.test", roundtrip.ClientConfig{}, logger, nil, nil),
	}
	t.Cleanup(func() {
		srv.portMu.Lock()
		for listenerPort, router := range srv.portRouters {
			router.cancel()
			if err := router.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				require.NoError(t, err)
			}
			delete(srv.portRouters, listenerPort)
		}
		srv.portMu.Unlock()
		srv.portRouterWg.Wait()
	})

	old := &proto.ProxyMapping{
		Id: "svc-update", AccountId: "account-1", Mode: "tcp",
		ListenPort: int32(port), Path: []*proto.PathMapping{{Target: "127.0.0.1:8080"}},
	}
	srv.storeMapping(old)
	updated := goproto.Clone(old).(*proto.ProxyMapping)
	updated.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED
	updated.PortMappings = []*proto.ServicePortMapping{
		{Protocol: "tcp", ListenPortStart: uint32(port), ListenPortEnd: uint32(port), TargetPortStart: 18080, TargetPortEnd: 18080},
	}

	require.Zero(t, srv.netbird.ClientCount())
	require.NoError(t, srv.modifyMapping(context.Background(), updated))
	assert.Zero(t, srv.netbird.ClientCount(), "route modification must not create or replace an embedded peer")
	assert.Same(t, updated, srv.loadMapping("svc-update"))
}

func reserveTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port) //nolint:gosec // OS-assigned test port
	require.NoError(t, listener.Close())
	return port
}

func reserveUDPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // OS-assigned test port
	require.NoError(t, listener.Close())
	return port
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
