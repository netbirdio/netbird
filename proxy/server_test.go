package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"
	goproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/proxy/internal/acme"
	proxyauth "github.com/netbirdio/netbird/proxy/internal/auth"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	httpproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	udprelay "github.com/netbirdio/netbird/proxy/internal/udp"
	shareddomain "github.com/netbirdio/netbird/shared/management/domain"
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

type serverHijackWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (w *serverHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
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

func TestServiceKeyForMappingIsStableAcrossRepresentations(t *testing.T) {
	srv := &Server{}
	want := roundtrip.ServiceIDKey("svc-1")

	for _, mapping := range []*proto.ProxyMapping{
		{Id: "svc-1", Domain: "tls.example.test", Mode: "tls", ListenPort: 443},
		{Id: "svc-1", Domain: "tls.example.test", Mode: "tcp", ListenPort: 443},
		{
			Id: "svc-1", Domain: "tls.example.test",
			PortMappings: []*proto.ServicePortMapping{
				{Protocol: "udp", ListenPortStart: 9001, ListenPortEnd: 9001, TargetPortStart: 9001, TargetPortEnd: 9001},
			},
		},
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

	assert.Equal(t, roundtrip.ServiceIDKey("svc-http"), srv.serviceKeyForMapping(&proto.ProxyMapping{
		Id: "svc-http", Domain: "app.example.test", Mode: "http",
	}))
}

func TestSparseRemoveUsesCachedAccountAndStableServiceIdentity(t *testing.T) {
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	var gotAccount types.AccountID
	var gotKey roundtrip.ServiceKey
	srv := &Server{
		Logger: quietLifecycleLogger(), meter: meter,
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping), svcPorts: make(map[types.ServiceID][]uint16),
		portRouters: make(map[uint16]*portRouter), udpRelays: make(map[udpRelayKey]*udprelay.Relay),
		crowdsecServices: make(map[types.ServiceID]bool),
		removePeer: func(_ context.Context, accountID types.AccountID, key roundtrip.ServiceKey) error {
			gotAccount, gotKey = accountID, key
			return nil
		},
	}
	srv.storeMapping(&proto.ProxyMapping{Id: "svc-1", AccountId: "acct-1", Domain: "old.example", Mode: "tcp"})

	srv.removeMapping(t.Context(), &proto.ProxyMapping{Id: "svc-1", Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED})

	assert.Equal(t, types.AccountID("acct-1"), gotAccount)
	assert.Equal(t, roundtrip.ServiceIDKey("svc-1"), gotKey)
	assert.Nil(t, srv.loadMapping("svc-1"))
}

func TestSnapshotCreateWithSameIDIsUpsert(t *testing.T) {
	srv := &Server{
		Logger: quietLifecycleLogger(), mgmtClient: statusUpdateOnlyClient{},
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping), crowdsecServices: make(map[types.ServiceID]bool),
		addPeer: func(context.Context, types.AccountID, roundtrip.ServiceKey, string, types.ServiceID) error {
			return errors.New("same-ID snapshot must not add a second peer")
		},
	}
	old := &proto.ProxyMapping{Id: "svc-1", AccountId: "acct", Mode: "http"}
	srv.storeMapping(old)
	updated := &proto.ProxyMapping{Id: "svc-1", AccountId: "acct", Mode: "http", Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED}

	require.NoError(t, srv.addMapping(t.Context(), updated))
	assert.Same(t, updated, srv.loadMapping("svc-1"))
}

func TestMappingRuntimeEqualIgnoresOnlyDeliveryMetadata(t *testing.T) {
	base := &proto.ProxyMapping{
		Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED,
		Id:   "svc-1", AccountId: "acct", Domain: "App.Example.TEST.", Mode: "tcp", AuthToken: "old-token",
		Path: []*proto.PathMapping{{Target: "127.0.0.1:1773"}},
		PortMappings: []*proto.ServicePortMapping{{
			Protocol: "tcp", ListenPortStart: 1773, ListenPortEnd: 1773, TargetPortStart: 1773, TargetPortEnd: 1773,
		}},
	}
	snapshot := goproto.Clone(base).(*proto.ProxyMapping)
	snapshot.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED
	snapshot.AuthToken = "refreshed-token"
	snapshot.Domain = "app.example.test"
	assert.True(t, mappingRuntimeEqual(base, snapshot))

	changedTarget := goproto.Clone(snapshot).(*proto.ProxyMapping)
	changedTarget.PortMappings[0].TargetPortStart = 2773
	changedTarget.PortMappings[0].TargetPortEnd = 2773
	assert.False(t, mappingRuntimeEqual(base, changedTarget))

	changedRestriction := goproto.Clone(snapshot).(*proto.ProxyMapping)
	changedRestriction.AccessRestrictions = &proto.AccessRestrictions{AllowedCidrs: []string{"192.0.2.0/24"}}
	assert.False(t, mappingRuntimeEqual(base, changedRestriction))
}

func TestSnapshotCreateWithUnchangedHTTPRuntimePreservesHijackedConnection(t *testing.T) {
	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	srv := &Server{
		Logger: logger, mgmtClient: statusUpdateOnlyClient{},
		proxy: httpproxy.NewReverseProxy(http.DefaultTransport, "https", nil, logger),
		auth:  proxyauth.NewMiddleware(logger, nil, nil), meter: meter,
		mainRouter: nbtcp.NewRouter(logger, nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}), mainPort: 8443,
		portRouters: make(map[uint16]*portRouter), svcPorts: make(map[types.ServiceID][]uint16),
		udpRelays: make(map[udpRelayKey]*udprelay.Relay), lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
		addPeer: func(context.Context, types.AccountID, roundtrip.ServiceKey, string, types.ServiceID) error {
			return errors.New("unchanged snapshot must not add a peer")
		},
	}
	mapping := &proto.ProxyMapping{
		Id: "svc-http", AccountId: "acct", Domain: "App.Example.TEST.", Mode: "http", AuthToken: "old-token",
		Path: []*proto.PathMapping{{Path: "/", Target: "http://127.0.0.1:8080"}},
	}
	require.NoError(t, srv.setupMappingRoutes(t.Context(), mapping))
	srv.storeMapping(mapping)
	t.Cleanup(func() { srv.cleanupMappingRoutes(mapping) })

	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close() })
	var hijacked net.Conn
	handler := srv.hijackTracker.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var hijackErr error
		hijacked, _, hijackErr = w.(http.Hijacker).Hijack()
		require.NoError(t, hijackErr)
	}))
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/socket", nil)
	request.Host = "APP.EXAMPLE.TEST.:443"
	handler.ServeHTTP(&serverHijackWriter{ResponseWriter: httptest.NewRecorder(), conn: proxySide}, request)
	require.NotNil(t, hijacked)
	t.Cleanup(func() { _ = hijacked.Close() })

	snapshot := goproto.Clone(mapping).(*proto.ProxyMapping)
	snapshot.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED
	snapshot.AuthToken = "refreshed-token"
	snapshot.Domain = "app.example.test"
	require.NoError(t, srv.addMapping(t.Context(), snapshot))
	assert.Same(t, snapshot, srv.loadMapping("svc-http"))

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := clientSide.Write([]byte("x"))
		writeDone <- writeErr
	}()
	require.NoError(t, hijacked.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 1)
	_, err = hijacked.Read(buf)
	require.NoError(t, err, "unchanged snapshot must not close the hijacked connection")
	require.NoError(t, <-writeDone)
	assert.Equal(t, byte('x'), buf[0])
	assert.Equal(t, 1, srv.hijackTracker.CloseByHost("app.example.test"), "connection must remain tracked")
}

func TestSnapshotCreateWithUnchangedL4RuntimePreservesListenersAndConnection(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	go func() {
		conn, acceptErr := backend.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	tcpPort := reserveTCPPort(t)
	udpPort := reserveUDPPort(t)
	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	srv := &Server{
		ctx: ctx, Logger: logger, mgmtClient: statusUpdateOnlyClient{}, meter: meter, mainPort: 8443,
		mainRouter:  nbtcp.NewRouter(logger, nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}),
		portRouters: make(map[uint16]*portRouter), svcPorts: make(map[types.ServiceID][]uint16),
		udpRelays: make(map[udpRelayKey]*udprelay.Relay), lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
		dialResolver: func(types.AccountID) (types.DialContextFunc, error) {
			return (&net.Dialer{}).DialContext, nil
		},
		addPeer: func(context.Context, types.AccountID, roundtrip.ServiceKey, string, types.ServiceID) error {
			return errors.New("unchanged snapshot must not add a peer")
		},
	}
	targetPort := uint32(backend.Addr().(*net.TCPAddr).Port) //nolint:gosec // OS-assigned test port
	mapping := &proto.ProxyMapping{
		Id: "svc-l4", AccountId: "acct", Domain: "App.Example.TEST.", Mode: "tcp", AuthToken: "old-token",
		Path: []*proto.PathMapping{{Target: backend.Addr().String()}},
		PortMappings: []*proto.ServicePortMapping{
			{Protocol: "tcp", ListenPortStart: uint32(tcpPort), ListenPortEnd: uint32(tcpPort), TargetPortStart: targetPort, TargetPortEnd: targetPort},
			{Protocol: "udp", ListenPortStart: uint32(udpPort), ListenPortEnd: uint32(udpPort), TargetPortStart: 9, TargetPortEnd: 9},
		},
	}
	require.NoError(t, srv.setupMappingRoutes(t.Context(), mapping))
	srv.storeMapping(mapping)
	t.Cleanup(func() {
		srv.cleanupMappingRoutes(mapping)
		srv.portRouterWg.Wait()
		srv.udpRelayWg.Wait()
	})

	srv.portMu.RLock()
	originalRouter := srv.portRouters[tcpPort]
	srv.portMu.RUnlock()
	srv.udpMu.Lock()
	originalUDP := srv.udpRelays[udpRelayKey{serviceID: "svc-l4", port: udpPort}]
	srv.udpMu.Unlock()
	require.NotNil(t, originalRouter)
	require.NotNil(t, originalUDP)
	// Directly constructed test servers do not initialize the production access
	// logger. Clear the typed-nil interface installed by getOrCreatePortRouter
	// before exercising the relay data path.
	originalRouter.router.SetAccessLogger(nil)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(tcpPort)), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	assertTCPEcho := func(payload string) {
		t.Helper()
		require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
		_, writeErr := conn.Write([]byte(payload))
		require.NoError(t, writeErr)
		buf := make([]byte, len(payload))
		_, readErr := io.ReadFull(conn, buf)
		require.NoError(t, readErr)
		assert.Equal(t, payload, string(buf))
	}
	assertTCPEcho("before")

	snapshot := goproto.Clone(mapping).(*proto.ProxyMapping)
	snapshot.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED
	snapshot.AuthToken = "refreshed-token"
	snapshot.Domain = "app.example.test"
	require.NoError(t, srv.addMapping(t.Context(), snapshot))
	assert.Same(t, snapshot, srv.loadMapping("svc-l4"))

	srv.portMu.RLock()
	assert.Same(t, originalRouter, srv.portRouters[tcpPort], "TCP listener/router must not be rebound")
	srv.portMu.RUnlock()
	srv.udpMu.Lock()
	assert.Same(t, originalUDP, srv.udpRelays[udpRelayKey{serviceID: "svc-l4", port: udpPort}], "UDP listener/relay must not restart")
	srv.udpMu.Unlock()
	assertTCPEcho("after")
}

func TestMappingsOwnSameRuntimeAllowsSNIAndFallbackCoexistence(t *testing.T) {
	srv := &Server{mainPort: 443}
	httpMapping := &proto.ProxyMapping{Id: "http", Domain: "app.example.test", Mode: "http"}
	mapping := func(id, mode, host string, port int32) *proto.ProxyMapping {
		return &proto.ProxyMapping{Id: id, Domain: host, Mode: mode, ListenPort: port}
	}

	assert.False(t, srv.mappingsOwnSameRuntime(httpMapping, mapping("tcp", "tcp", "app.example.test", 443)),
		"HTTP SNI and raw TCP fallback can coexist on the main router")
	assert.True(t, srv.mappingsOwnSameRuntime(httpMapping, mapping("tls", "tls", "app.example.test", 443)))
	assert.False(t, srv.mappingsOwnSameRuntime(httpMapping, mapping("tls-other", "tls", "other.example.test", 443)))
	assert.False(t, srv.mappingsOwnSameRuntime(
		mapping("tcp", "tcp", "app.example.test", 1773), mapping("tls", "tls", "app.example.test", 1773),
	), "TLS SNI and raw TCP fallback can coexist on a custom router")
	assert.True(t, srv.mappingsOwnSameRuntime(
		mapping("tcp-a", "tcp", "a.example.test", 1773), mapping("tcp-b", "tcp", "b.example.test", 1773),
	))
	assert.True(t, srv.mappingsOwnSameRuntime(
		mapping("udp-a", "udp", "a.example.test", 9001), mapping("udp-b", "udp", "b.example.test", 9001),
	))
	assert.False(t, srv.mappingsOwnSameRuntime(
		mapping("tcp", "tcp", "a.example.test", 9001), mapping("udp", "udp", "a.example.test", 9001),
	))
}

func TestL4LifecyclePreservesSharedDomainHTTPState(t *testing.T) {
	for _, operation := range []string{"delete", "update"} {
		t.Run(operation, func(t *testing.T) {
			srv, l4Mapping, httpMapping, certManager := setupSharedDomainHTTPAndTLS(t)

			switch operation {
			case "delete":
				srv.removeMapping(t.Context(), l4Mapping)
				assert.Nil(t, srv.loadMapping(types.ServiceID(l4Mapping.GetId())))
			case "update":
				updated := goproto.Clone(l4Mapping).(*proto.ProxyMapping)
				updated.Type = proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED
				updated.Path[0].Target = "127.0.0.1:10443"
				require.NoError(t, srv.modifyMapping(t.Context(), updated))
				assert.Same(t, updated, srv.loadMapping(types.ServiceID(l4Mapping.GetId())))
			}

			assert.Equal(t, 1, certManager.TotalDomains(), "L4 lifecycle must preserve HTTP ACME ownership")
			assert.Equal(t, http.StatusForbidden, protectedDomainStatus(srv.auth, httpMapping.Host),
				"L4 lifecycle must preserve HTTP auth configuration")
			assert.True(t, srv.proxy.RemoveMapping(httpMapping),
				"L4 lifecycle must preserve the HTTP reverse-proxy mapping")

			// Deleting the L4 route (a no-op after the delete case) must still
			// leave the same-host HTTP route registered.
			srv.mainRouter.RemoveRoute(nbtcp.SNIHost(httpMapping.Host), types.ServiceID(l4Mapping.GetId()))
			assert.False(t, srv.mainRouter.IsEmpty(), "same-domain HTTP SNI route must remain")
			srv.mainRouter.RemoveRoute(nbtcp.SNIHost(httpMapping.Host), httpMapping.ID)
			assert.True(t, srv.mainRouter.IsEmpty())
		})
	}
}

func TestStaleHTTPCleanupPreservesReplacementOwner(t *testing.T) {
	srv, _, httpMapping, certManager := setupSharedDomainHTTPAndTLS(t)
	stale := &proto.ProxyMapping{
		Id: "svc-stale-http", AccountId: string(httpMapping.AccountID), Domain: "SHARED.EXAMPLE.TEST.", Mode: "http",
	}

	srv.cleanupMappingRoutes(stale)

	assert.Equal(t, 1, certManager.TotalDomains())
	assert.Equal(t, http.StatusForbidden, protectedDomainStatus(srv.auth, "SHARED.EXAMPLE.TEST."))
	owner, ok := srv.proxy.MappingOwner(httpMapping.Host)
	require.True(t, ok)
	assert.Equal(t, httpMapping.ID, owner)
	assert.False(t, srv.mainRouter.IsEmpty(), "stale service-ID cleanup must preserve replacement SNI route")
}

func setupSharedDomainHTTPAndTLS(t *testing.T) (*Server, *proto.ProxyMapping, httpproxy.Mapping, *acme.Manager) {
	t.Helper()

	const host = "shared.example.test"
	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)

	wildcardDir := t.TempDir()
	writeTestWildcardCertificate(t, wildcardDir, "*.example.test")

	certManager, err := acme.NewManager(acme.ManagerConfig{
		CertDir:     t.TempDir(),
		ACMEURL:     "https://acme.invalid/directory",
		WildcardDir: wildcardDir,
	}, nil, logger, meter)
	require.NoError(t, err)

	authMiddleware := proxyauth.NewMiddleware(logger, nil, nil)
	require.NoError(t, authMiddleware.AddDomain(
		host, nil, "", time.Minute, types.AccountID("account-http"), types.ServiceID("svc-http"), nil, true,
	))

	httpRuntime := httpproxy.NewReverseProxy(http.DefaultTransport, "https", nil, logger)
	httpMapping := httpproxy.Mapping{
		ID:        types.ServiceID("svc-http"),
		AccountID: types.AccountID("account-http"),
		Host:      host,
		Paths:     map[string]*httpproxy.PathTarget{},
	}
	httpRuntime.AddMapping(httpMapping)
	meter.AddMapping(httpMapping)
	require.True(t, certManager.AddDomain(shareddomain.Domain(host), httpMapping.AccountID, httpMapping.ID),
		"wildcard fixture must make certificate registration synchronous")

	mainRouter := nbtcp.NewRouter(logger, nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	mainRouter.AddRoute(nbtcp.SNIHost(host), nbtcp.Route{
		Type:      nbtcp.RouteHTTP,
		AccountID: httpMapping.AccountID,
		ServiceID: httpMapping.ID,
		Domain:    host,
	})

	srv := &Server{
		Logger:           logger,
		mgmtClient:       statusUpdateOnlyClient{},
		proxy:            httpRuntime,
		auth:             authMiddleware,
		acme:             certManager,
		meter:            meter,
		mainRouter:       mainRouter,
		mainPort:         443,
		portRouters:      make(map[uint16]*portRouter),
		svcPorts:         make(map[types.ServiceID][]uint16),
		udpRelays:        make(map[udpRelayKey]*udprelay.Relay),
		lastMappings:     make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
		removePeer: func(context.Context, types.AccountID, roundtrip.ServiceKey) error {
			return nil
		},
	}

	l4Mapping := &proto.ProxyMapping{
		Id:         "svc-tls",
		AccountId:  "account-l4",
		Domain:     host,
		Mode:       "tls",
		ListenPort: 443,
		Path: []*proto.PathMapping{
			{Target: "127.0.0.1:9443"},
		},
	}
	require.NoError(t, srv.setupTLSMapping(t.Context(), l4Mapping))
	srv.storeMapping(l4Mapping)

	t.Cleanup(func() {
		if current := srv.loadMapping(types.ServiceID(l4Mapping.GetId())); current != nil {
			srv.cleanupMappingRoutes(current)
		}
		srv.mainRouter.RemoveRoute(nbtcp.SNIHost(host), httpMapping.ID)
		srv.auth.RemoveDomain(host)
		srv.proxy.RemoveMapping(httpMapping)
		certManager.RemoveDomain(shareddomain.Domain(host))
	})

	return srv, l4Mapping, httpMapping, certManager
}

func writeTestWildcardCertificate(t *testing.T, dir, dnsName string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	privateKey, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "shared.crt"), pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certificate,
	}), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "shared.key"), pem.EncodeToMemory(&pem.Block{
		Type: "EC PRIVATE KEY", Bytes: privateKey,
	}), 0o600))
}

func protectedDomainStatus(middleware *proxyauth.Middleware, host string) int {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	request.Host = host
	middleware.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)
	return recorder.Code
}

func TestHTTPRemovalPreservesSharedDomainL4Listener(t *testing.T) {
	port := reserveTCPPort(t)
	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	srv := &Server{
		ctx:              ctx,
		Logger:           logger,
		mgmtClient:       statusUpdateOnlyClient{},
		proxy:            httpproxy.NewReverseProxy(http.DefaultTransport, "https", nil, logger),
		auth:             proxyauth.NewMiddleware(logger, nil, nil),
		meter:            meter,
		mainRouter:       nbtcp.NewRouter(logger, nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}),
		mainPort:         8443,
		portRouters:      make(map[uint16]*portRouter),
		svcPorts:         make(map[types.ServiceID][]uint16),
		udpRelays:        make(map[udpRelayKey]*udprelay.Relay),
		lastMappings:     make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
		removePeer: func(context.Context, types.AccountID, roundtrip.ServiceKey) error {
			return nil
		},
	}

	const host = "shared.example.test"
	l4Mapping := &proto.ProxyMapping{
		Id:         "svc-tcp",
		AccountId:  "account-l4",
		Domain:     host,
		Mode:       "tcp",
		ListenPort: int32(port),
		Path:       []*proto.PathMapping{{Target: "127.0.0.1:22"}},
	}
	require.NoError(t, srv.setupTCPMapping(t.Context(), l4Mapping))
	t.Cleanup(func() {
		srv.cleanupMappingRoutes(l4Mapping)
		srv.portRouterWg.Wait()
	})

	httpMapping := &proto.ProxyMapping{
		Id:        "svc-http",
		AccountId: "account-http",
		Domain:    host,
		Mode:      "http",
	}
	srv.mainRouter.AddRoute(nbtcp.SNIHost(host), nbtcp.Route{
		Type: nbtcp.RouteHTTP, AccountID: "account-http", ServiceID: "svc-http", Domain: host,
	})
	srv.storeMapping(httpMapping)

	srv.removeMapping(t.Context(), httpMapping)

	srv.portMu.RLock()
	portRuntime, listenerExists := srv.portRouters[port]
	trackedPorts := append([]uint16(nil), srv.svcPorts[types.ServiceID(l4Mapping.GetId())]...)
	srv.portMu.RUnlock()
	require.True(t, listenerExists, "removing HTTP must not close a same-domain L4 listener")
	assert.False(t, portRuntime.router.IsEmpty(), "L4 fallback route must remain installed")
	assert.Equal(t, []uint16{port}, trackedPorts)

	second, bindErr := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if bindErr == nil {
		require.NoError(t, second.Close())
	}
	require.Error(t, bindErr, "same-domain L4 listener must remain bound after HTTP removal")
}

func TestSnapshotReplacementPreservesSharedHTTPAndRebindsTCPRangeAndUDP(t *testing.T) {
	start := reserveTCPPortRange(t, 2)
	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	httpRuntime := httpproxy.NewReverseProxy(http.DefaultTransport, "https", nil, logger)
	httpRuntime.AddMapping(httpproxy.Mapping{ID: "svc-http", AccountID: "acct", Host: "shared.example.test", Paths: map[string]*httpproxy.PathTarget{}})
	authMiddleware := proxyauth.NewMiddleware(logger, nil, nil)
	require.NoError(t, authMiddleware.AddDomain("shared.example.test", nil, "", 0, "acct", "svc-http", nil, true))

	srv := &Server{
		ctx: ctx, Logger: logger, mgmtClient: statusUpdateOnlyClient{}, proxy: httpRuntime, auth: authMiddleware,
		meter: meter, mainRouter: nbtcp.NewRouter(logger, nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}), mainPort: 8443,
		portRouters: make(map[uint16]*portRouter), svcPorts: make(map[types.ServiceID][]uint16),
		udpRelays: make(map[udpRelayKey]*udprelay.Relay), lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
		dialResolver:     func(types.AccountID) (types.DialContextFunc, error) { return (&net.Dialer{}).DialContext, nil },
		addPeer: func(context.Context, types.AccountID, roundtrip.ServiceKey, string, types.ServiceID) error {
			return nil
		},
		removePeer: func(context.Context, types.AccountID, roundtrip.ServiceKey) error { return nil },
	}
	httpProto := &proto.ProxyMapping{Id: "svc-http", AccountId: "acct", Domain: "shared.example.test", Mode: "http"}
	srv.storeMapping(httpProto)

	makeL4 := func(id string) *proto.ProxyMapping {
		return &proto.ProxyMapping{
			Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, Id: id, AccountId: "acct", Domain: "shared.example.test", Mode: "tcp",
			Path: []*proto.PathMapping{{Target: "127.0.0.1:8080"}},
			PortMappings: []*proto.ServicePortMapping{
				{Protocol: "tcp", ListenPortStart: uint32(start), ListenPortEnd: uint32(start + 1), TargetPortStart: 1773, TargetPortEnd: 1774},
				{Protocol: "udp", ListenPortStart: uint32(start), ListenPortEnd: uint32(start), TargetPortStart: 9001, TargetPortEnd: 9001},
			},
		}
	}
	old := makeL4("svc-old")
	require.NoError(t, srv.setupMappingRoutes(t.Context(), old))
	srv.storeMapping(old)

	replacement := makeL4("svc-new")
	require.NoError(t, srv.addMapping(t.Context(), replacement))
	assert.Nil(t, srv.loadMapping("svc-old"))
	assert.NotNil(t, srv.loadMapping("svc-new"))
	owner, ok := srv.proxy.MappingOwner("SHARED.EXAMPLE.TEST.")
	require.True(t, ok)
	assert.Equal(t, types.ServiceID("svc-http"), owner)
	assert.Equal(t, http.StatusForbidden, protectedDomainStatus(srv.auth, "SHARED.EXAMPLE.TEST."))

	for port := start; port <= start+1; port++ {
		router := srv.routerForPortExisting(port)
		require.NotNil(t, router)
		fallbackOwner, exists := router.FallbackOwner()
		require.True(t, exists)
		assert.Equal(t, types.ServiceID("svc-new"), fallbackOwner)
	}
	srv.udpMu.Lock()
	_, newUDP := srv.udpRelays[udpRelayKey{serviceID: "svc-new", port: start}]
	_, oldUDP := srv.udpRelays[udpRelayKey{serviceID: "svc-old", port: start}]
	srv.udpMu.Unlock()
	assert.True(t, newUDP)
	assert.False(t, oldUDP)

	// A late stale cleanup record for the old ID cannot tear down the new
	// fallback/UDP ownership or the shared HTTP route.
	srv.cleanupMappingRoutes(old)
	owner, ok = srv.proxy.MappingOwner("shared.example.test")
	require.True(t, ok)
	assert.Equal(t, types.ServiceID("svc-http"), owner)
	for port := start; port <= start+1; port++ {
		fallbackOwner, exists := srv.routerForPortExisting(port).FallbackOwner()
		require.True(t, exists)
		assert.Equal(t, types.ServiceID("svc-new"), fallbackOwner)
	}
	srv.udpMu.Lock()
	_, newUDP = srv.udpRelays[udpRelayKey{serviceID: "svc-new", port: start}]
	srv.udpMu.Unlock()
	assert.True(t, newUDP)

	t.Cleanup(func() {
		srv.cleanupMappingRoutes(replacement)
		srv.portRouterWg.Wait()
		srv.udpRelayWg.Wait()
	})
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

func TestFailedModifyRestoresPreviousRuntimeAndCache(t *testing.T) {
	port := reserveTCPPort(t)
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	srv := &Server{
		ctx: ctx, Logger: quietLifecycleLogger(), mgmtClient: statusUpdateOnlyClient{}, meter: meter, mainPort: 8443,
		mainRouter:  nbtcp.NewRouter(quietLifecycleLogger(), nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}),
		portRouters: make(map[uint16]*portRouter), svcPorts: make(map[types.ServiceID][]uint16),
		udpRelays: make(map[udpRelayKey]*udprelay.Relay), lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
	}
	old := &proto.ProxyMapping{
		Id: "svc-rollback", AccountId: "acct", Domain: "shared.example.test", Mode: "tcp", ListenPort: int32(port),
		Path: []*proto.PathMapping{{Target: "127.0.0.1:1773"}},
	}
	require.NoError(t, srv.setupMappingRoutes(t.Context(), old))
	srv.storeMapping(old)
	t.Cleanup(func() {
		if current := srv.loadMapping("svc-rollback"); current != nil {
			srv.cleanupMappingRoutes(current)
		}
		srv.portRouterWg.Wait()
	})

	broken := goproto.Clone(old).(*proto.ProxyMapping)
	broken.Path[0].Target = "missing-port"
	require.Error(t, srv.modifyMapping(t.Context(), broken))
	assert.Same(t, old, srv.loadMapping("svc-rollback"), "cache must describe the restored runtime")
	router := srv.routerForPortExisting(port)
	require.NotNil(t, router)
	owner, ok := router.FallbackOwner()
	require.True(t, ok)
	assert.Equal(t, types.ServiceID("svc-rollback"), owner)
}

func TestFailedSnapshotReplacementRestoresPreviousOwner(t *testing.T) {
	port := reserveTCPPort(t)
	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	srv := &Server{
		ctx: ctx, Logger: logger, mgmtClient: statusUpdateOnlyClient{}, meter: meter, mainPort: 8443,
		mainRouter:  nbtcp.NewRouter(logger, nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}),
		portRouters: make(map[uint16]*portRouter), svcPorts: make(map[types.ServiceID][]uint16),
		udpRelays: make(map[udpRelayKey]*udprelay.Relay), lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[types.ServiceID]bool),
		addPeer: func(context.Context, types.AccountID, roundtrip.ServiceKey, string, types.ServiceID) error {
			return nil
		},
		removePeer: func(context.Context, types.AccountID, roundtrip.ServiceKey) error { return nil },
	}
	old := &proto.ProxyMapping{
		Id: "svc-old", AccountId: "acct", Domain: "shared.example.test", Mode: "tcp", ListenPort: int32(port),
		Path: []*proto.PathMapping{{Target: "127.0.0.1:1773"}},
	}
	require.NoError(t, srv.setupMappingRoutes(t.Context(), old))
	srv.storeMapping(old)
	t.Cleanup(func() {
		if current := srv.loadMapping("svc-old"); current != nil {
			srv.cleanupMappingRoutes(current)
		}
		srv.portRouterWg.Wait()
	})

	replacement := &proto.ProxyMapping{
		Type: proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:   "svc-new", AccountId: "acct", Domain: "shared.example.test", Mode: "tcp", ListenPort: int32(port),
		Path: []*proto.PathMapping{{Target: "missing-port"}},
	}
	require.Error(t, srv.addMapping(t.Context(), replacement))
	assert.Same(t, old, srv.loadMapping("svc-old"))
	assert.Nil(t, srv.loadMapping("svc-new"))
	owner, ok := srv.routerForPortExisting(port).FallbackOwner()
	require.True(t, ok)
	assert.Equal(t, types.ServiceID("svc-old"), owner)
}

func reserveTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port) //nolint:gosec // OS-assigned test port
	require.NoError(t, listener.Close())
	return port
}

func reserveTCPPortRange(t *testing.T, count uint16) uint16 {
	t.Helper()
	for range 100 {
		start := reserveTCPPort(t)
		if uint32(start)+uint32(count)-1 > 65535 {
			continue
		}
		listeners := make([]net.Listener, 0, count)
		available := true
		for offset := uint16(0); offset < count; offset++ {
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", start+offset))
			if err != nil {
				available = false
				break
			}
			listeners = append(listeners, listener)
		}
		for _, listener := range listeners {
			require.NoError(t, listener.Close())
		}
		if available {
			return start
		}
	}
	t.Fatal("failed to reserve a contiguous TCP port range")
	return 0
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
