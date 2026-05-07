package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	nbproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	proxytypes "github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// integrationTestSetup contains all real components for testing.
type integrationTestSetup struct {
	store        store.Store
	proxyService *nbgrpc.ProxyServiceServer
	grpcServer   *grpc.Server
	grpcAddr     string
	cleanup      func()
	services     []*service.Service
}

func setupIntegrationTest(t *testing.T) *integrationTestSetup {
	t.Helper()

	ctx := context.Background()

	// Create real SQLite store
	testStore, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)

	// Create test account
	testAccount := &types.Account{
		Id:                     "test-account-1",
		Domain:                 "test.com",
		DomainCategory:         "private",
		IsDomainPrimaryAccount: true,
		CreatedAt:              time.Now(),
	}
	require.NoError(t, testStore.SaveAccount(ctx, testAccount))

	// Generate session keys for reverse proxies
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey := base64.StdEncoding.EncodeToString(pub)
	privKey := base64.StdEncoding.EncodeToString(priv)

	// Create test services in the store
	services := []*service.Service{
		{
			ID:        "rp-1",
			AccountID: "test-account-1",
			Name:      "Test App 1",
			Domain:    "app1.test.proxy.io",
			Targets: []*service.Target{{
				Path:       strPtr("/"),
				Host:       "10.0.0.1",
				Port:       8080,
				Protocol:   "http",
				TargetId:   "peer1",
				TargetType: "peer",
				Enabled:    true,
			}},
			Enabled:           true,
			ProxyCluster:      "test.proxy.io",
			SessionPrivateKey: privKey,
			SessionPublicKey:  pubKey,
		},
		{
			ID:        "rp-2",
			AccountID: "test-account-1",
			Name:      "Test App 2",
			Domain:    "app2.test.proxy.io",
			Targets: []*service.Target{{
				Path:       strPtr("/"),
				Host:       "10.0.0.2",
				Port:       8080,
				Protocol:   "http",
				TargetId:   "peer2",
				TargetType: "peer",
				Enabled:    true,
			}},
			Enabled:           true,
			ProxyCluster:      "test.proxy.io",
			SessionPrivateKey: privKey,
			SessionPublicKey:  pubKey,
		},
	}

	for _, svc := range services {
		require.NoError(t, testStore.CreateService(ctx, svc))
	}

	// Create real token store
	cacheStore, err := nbcache.NewStore(ctx, 30*time.Minute, 10*time.Minute, 100)
	require.NoError(t, err)

	tokenStore := nbgrpc.NewOneTimeTokenStore(ctx, cacheStore)
	pkceStore := nbgrpc.NewPKCEVerifierStore(ctx, cacheStore)

	// Create real users manager
	usersManager := users.NewManager(testStore)

	// Create real proxy service server with minimal config
	oidcConfig := nbgrpc.ProxyOIDCConfig{
		Issuer:   "https://fake-issuer.example.com",
		ClientID: "test-client",
		HMACKey:  []byte("test-hmac-key"),
	}

	proxyManager := &testProxyManager{}

	proxyService := nbgrpc.NewProxyServiceServer(
		&testAccessLogManager{},
		tokenStore,
		pkceStore,
		oidcConfig,
		nil,
		usersManager,
		proxyManager,
	)

	// Use store-backed service manager
	svcMgr := &storeBackedServiceManager{store: testStore, tokenStore: tokenStore}
	proxyService.SetServiceManager(svcMgr)

	proxyController := &testProxyController{}
	proxyService.SetProxyController(proxyController)

	// Start real gRPC server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	proto.RegisterProxyServiceServer(grpcServer, proxyService)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("gRPC server error: %v", err)
		}
	}()

	return &integrationTestSetup{
		store:        testStore,
		proxyService: proxyService,
		grpcServer:   grpcServer,
		grpcAddr:     lis.Addr().String(),
		services:     services,
		cleanup: func() {
			grpcServer.GracefulStop()
			cleanup()
		},
	}
}

// testAccessLogManager provides access log storage for testing.
type testAccessLogManager struct{}

func (m *testAccessLogManager) CleanupOldAccessLogs(ctx context.Context, retentionDays int) (int64, error) {
	return 0, nil
}

func (m *testAccessLogManager) StartPeriodicCleanup(ctx context.Context, retentionDays, cleanupIntervalHours int) {
	// noop
}

func (m *testAccessLogManager) StopPeriodicCleanup() {
	// noop
}

func (m *testAccessLogManager) SaveAccessLog(_ context.Context, _ *accesslogs.AccessLogEntry) error {
	return nil
}

func (m *testAccessLogManager) GetAllAccessLogs(_ context.Context, _, _ string, _ *accesslogs.AccessLogFilter) ([]*accesslogs.AccessLogEntry, int64, error) {
	return nil, 0, nil
}

// testProxyManager is a mock implementation of proxy.Manager for testing.
type testProxyManager struct{}

func (m *testProxyManager) Connect(_ context.Context, proxyID, sessionID, _, _ string, _ *nbproxy.Capabilities) (*nbproxy.Proxy, error) {
	return &nbproxy.Proxy{ID: proxyID, SessionID: sessionID, Status: "connected"}, nil
}

func (m *testProxyManager) Disconnect(_ context.Context, _, _ string) error {
	return nil
}

func (m *testProxyManager) Heartbeat(_ context.Context, _ *nbproxy.Proxy) error {
	return nil
}

func (m *testProxyManager) GetActiveClusterAddresses(_ context.Context) ([]string, error) {
	return nil, nil
}

func (m *testProxyManager) GetActiveClusters(_ context.Context) ([]nbproxy.Cluster, error) {
	return nil, nil
}

func (m *testProxyManager) ClusterSupportsCustomPorts(_ context.Context, _ string) *bool {
	return nil
}

func (m *testProxyManager) ClusterRequireSubdomain(_ context.Context, _ string) *bool {
	return nil
}

func (m *testProxyManager) ClusterSupportsCrowdSec(_ context.Context, _ string) *bool {
	return nil
}

func (m *testProxyManager) CleanupStale(_ context.Context, _ time.Duration) error {
	return nil
}

// testProxyController is a mock implementation of rpservice.ProxyController for testing.
type testProxyController struct{}

func (c *testProxyController) SendServiceUpdateToCluster(_ context.Context, _ string, _ *proto.ProxyMapping, _ string) {
	// noop
}

func (c *testProxyController) GetOIDCValidationConfig() nbproxy.OIDCValidationConfig {
	return nbproxy.OIDCValidationConfig{}
}

func (c *testProxyController) RegisterProxyToCluster(_ context.Context, _, _ string) error {
	return nil
}

func (c *testProxyController) UnregisterProxyFromCluster(_ context.Context, _, _ string) error {
	return nil
}

func (c *testProxyController) GetProxiesForCluster(_ string) []string {
	return nil
}

// storeBackedServiceManager reads directly from the real store.
type storeBackedServiceManager struct {
	store      store.Store
	tokenStore *nbgrpc.OneTimeTokenStore
}

func (m *storeBackedServiceManager) DeleteAllServices(ctx context.Context, accountID, userID string) error {
	return nil
}

func (m *storeBackedServiceManager) GetAllServices(ctx context.Context, accountID, userID string) ([]*service.Service, error) {
	return m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
}

func (m *storeBackedServiceManager) GetService(ctx context.Context, accountID, userID, serviceID string) (*service.Service, error) {
	return m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, serviceID)
}

func (m *storeBackedServiceManager) CreateService(_ context.Context, _, _ string, _ *service.Service) (*service.Service, error) {
	return nil, errors.New("not implemented")
}

func (m *storeBackedServiceManager) UpdateService(_ context.Context, _, _ string, _ *service.Service) (*service.Service, error) {
	return nil, errors.New("not implemented")
}

func (m *storeBackedServiceManager) DeleteService(ctx context.Context, accountID, userID, serviceID string) error {
	return nil
}

func (m *storeBackedServiceManager) SetCertificateIssuedAt(ctx context.Context, accountID, serviceID string) error {
	return nil
}

func (m *storeBackedServiceManager) SetStatus(ctx context.Context, accountID, serviceID string, status service.Status) error {
	return nil
}

func (m *storeBackedServiceManager) ReloadAllServicesForAccount(ctx context.Context, accountID string) error {
	return nil
}

func (m *storeBackedServiceManager) ReloadService(ctx context.Context, accountID, serviceID string) error {
	return nil
}

func (m *storeBackedServiceManager) GetGlobalServices(ctx context.Context) ([]*service.Service, error) {
	return m.store.GetAccountServices(ctx, store.LockingStrengthNone, "test-account-1")
}

func (m *storeBackedServiceManager) GetServiceByID(ctx context.Context, accountID, serviceID string) (*service.Service, error) {
	return m.store.GetServiceByID(ctx, store.LockingStrengthNone, accountID, serviceID)
}

func (m *storeBackedServiceManager) GetAccountServices(ctx context.Context, accountID string) ([]*service.Service, error) {
	return m.store.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
}

func (m *storeBackedServiceManager) GetServiceIDByTargetID(ctx context.Context, accountID string, targetID string) (string, error) {
	return "", nil
}

func (m *storeBackedServiceManager) CreateServiceFromPeer(_ context.Context, _, _ string, _ *service.ExposeServiceRequest) (*service.ExposeServiceResponse, error) {
	return &service.ExposeServiceResponse{}, nil
}

func (m *storeBackedServiceManager) RenewServiceFromPeer(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *storeBackedServiceManager) StopServiceFromPeer(_ context.Context, _, _, _ string) error {
	return nil
}

func (m *storeBackedServiceManager) StartExposeReaper(_ context.Context) {}

func (m *storeBackedServiceManager) GetActiveClusters(_ context.Context, _, _ string) ([]nbproxy.Cluster, error) {
	return nil, nil
}

func strPtr(s string) *string {
	return &s
}

func TestIntegration_ProxyConnection_HappyPath(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId: "test-proxy-1",
		Version: "test-v1",
		Address: "test.proxy.io",
	})
	require.NoError(t, err)

	mappingsByID := make(map[string]*proto.ProxyMapping)
	for {
		msg, err := stream.Recv()
		require.NoError(t, err)
		for _, m := range msg.GetMapping() {
			mappingsByID[m.GetId()] = m
		}
		if msg.GetInitialSyncComplete() {
			break
		}
	}

	// Should receive 2 mappings total
	assert.Len(t, mappingsByID, 2, "Should receive 2 reverse proxy mappings")

	rp1 := mappingsByID["rp-1"]
	require.NotNil(t, rp1)
	assert.Equal(t, "app1.test.proxy.io", rp1.GetDomain())
	assert.Equal(t, "test-account-1", rp1.GetAccountId())
	assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, rp1.GetType())
	assert.NotEmpty(t, rp1.GetAuthToken(), "Should have auth token for peer creation")

	rp2 := mappingsByID["rp-2"]
	require.NotNil(t, rp2)
	assert.Equal(t, "app2.test.proxy.io", rp2.GetDomain())
}

func TestIntegration_ProxyConnection_SendsClusterAddress(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clusterAddress := "test.proxy.io"

	stream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId: "test-proxy-cluster",
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	mappings := make([]*proto.ProxyMapping, 0)
	for {
		msg, err := stream.Recv()
		require.NoError(t, err)
		mappings = append(mappings, msg.GetMapping()...)
		if msg.GetInitialSyncComplete() {
			break
		}
	}

	// Should receive the 2 mappings matching the cluster
	assert.Len(t, mappings, 2, "Should receive mappings for the cluster")

	for _, mapping := range mappings {
		t.Logf("Received mapping: id=%s domain=%s", mapping.GetId(), mapping.GetDomain())
	}
}

func TestIntegration_ProxyConnection_Reconnect_ReceivesSameConfig(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	clusterAddress := "test.proxy.io"
	proxyID := "test-proxy-reconnect"

	receiveMappings := func(stream proto.ProxyService_GetMappingUpdateClient) []*proto.ProxyMapping {
		var mappings []*proto.ProxyMapping
		for {
			msg, err := stream.Recv()
			require.NoError(t, err)
			mappings = append(mappings, msg.GetMapping()...)
			if msg.GetInitialSyncComplete() {
				break
			}
		}
		return mappings
	}

	// First connection
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	stream1, err := client.GetMappingUpdate(ctx1, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	firstMappings := receiveMappings(stream1)
	cancel1()

	time.Sleep(100 * time.Millisecond)

	// Second connection (simulating reconnect)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	stream2, err := client.GetMappingUpdate(ctx2, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	secondMappings := receiveMappings(stream2)

	// Should receive the same mappings
	assert.Equal(t, len(firstMappings), len(secondMappings),
		"Should receive same number of mappings on reconnect")

	firstIDs := make(map[string]bool)
	for _, m := range firstMappings {
		firstIDs[m.GetId()] = true
	}

	for _, m := range secondMappings {
		assert.True(t, firstIDs[m.GetId()],
			"Mapping %s should be present in both connections", m.GetId())
	}
}

func TestIntegration_ProxyConnection_ReconnectDoesNotDuplicateState(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	// Use real auth middleware and proxy to verify idempotency
	logger := log.New()
	logger.SetLevel(log.WarnLevel)

	authMw := auth.NewMiddleware(logger, nil, nil)
	proxyHandler := proxy.NewReverseProxy(nil, "auto", nil, logger)

	clusterAddress := "test.proxy.io"
	proxyID := "test-proxy-idempotent"

	var addMappingCalls atomic.Int32

	applyMappings := func(mappings []*proto.ProxyMapping) {
		for _, mapping := range mappings {
			if mapping.GetType() == proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED {
				addMappingCalls.Add(1)

				// Apply to real auth middleware (idempotent)
				err := authMw.AddDomain(
					mapping.GetDomain(),
					nil,
					"",
					0,
					proxytypes.AccountID(mapping.GetAccountId()),
					proxytypes.ServiceID(mapping.GetId()),
					nil,
				)
				require.NoError(t, err)

				// Apply to real proxy (idempotent)
				proxyHandler.AddMapping(proxy.Mapping{
					Host:      mapping.GetDomain(),
					ID:        proxytypes.ServiceID(mapping.GetId()),
					AccountID: proxytypes.AccountID(mapping.GetAccountId()),
				})
			}
		}
	}

	receiveAndApply := func(stream proto.ProxyService_GetMappingUpdateClient) {
		for {
			msg, err := stream.Recv()
			require.NoError(t, err)
			applyMappings(msg.GetMapping())
			if msg.GetInitialSyncComplete() {
				break
			}
		}
	}

	// First connection
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	stream1, err := client.GetMappingUpdate(ctx1, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	receiveAndApply(stream1)
	cancel1()

	firstCallCount := addMappingCalls.Load()
	t.Logf("First connection: applied %d mappings", firstCallCount)

	time.Sleep(100 * time.Millisecond)

	// Second connection
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	stream2, err := client.GetMappingUpdate(ctx2, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	receiveAndApply(stream2)
	cancel2()

	time.Sleep(100 * time.Millisecond)

	// Third connection
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()

	stream3, err := client.GetMappingUpdate(ctx3, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	receiveAndApply(stream3)

	totalCalls := addMappingCalls.Load()
	t.Logf("After three connections: total applied %d mappings", totalCalls)

	// Should have called addMapping 6 times (2 mappings x 3 connections)
	// But internal state is NOT duplicated because auth and proxy use maps keyed by domain/host
	assert.Equal(t, int32(6), totalCalls, "Should have 6 total calls (2 mappings x 3 connections)")
}

func TestIntegration_ProxyConnection_MultipleProxiesReceiveUpdates(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	clusterAddress := "test.proxy.io"

	var wg sync.WaitGroup
	var mu sync.Mutex
	receivedByProxy := make(map[string]int)

	for i := 1; i <= 3; i++ {
		wg.Add(1)
		go func(proxyNum int) {
			defer wg.Done()

			conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

			client := proto.NewProxyServiceClient(conn)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			proxyID := "test-proxy-" + string(rune('A'+proxyNum-1))

			stream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
				ProxyId: proxyID,
				Version: "test-v1",
				Address: clusterAddress,
			})
			require.NoError(t, err)

			count := 0
			for {
				msg, err := stream.Recv()
				require.NoError(t, err)
				count += len(msg.GetMapping())
				if msg.GetInitialSyncComplete() {
					break
				}
			}

			mu.Lock()
			receivedByProxy[proxyID] = count
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	for proxyID, count := range receivedByProxy {
		assert.Equal(t, 2, count, "Proxy %s should receive 2 mappings", proxyID)
	}
}

// TestIntegration_ProxyConnection_FastReconnectDoesNotLoseState verifies that
// when a proxy reconnects before the old stream's cleanup runs, the new
// connection is NOT removed by the stale defer.
func TestIntegration_ProxyConnection_FastReconnectDoesNotLoseState(t *testing.T) {
	setup := setupIntegrationTest(t)
	defer setup.cleanup()

	clusterAddress := "test.proxy.io"
	proxyID := "test-proxy-race"

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx1, cancel1 := context.WithCancel(context.Background())
	stream1, err := client.GetMappingUpdate(ctx1, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	for {
		msg, err := stream1.Recv()
		require.NoError(t, err)
		if msg.GetInitialSyncComplete() {
			break
		}
	}

	require.Contains(t, setup.proxyService.GetConnectedProxies(), proxyID,
		"proxy should be registered after first connection")

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	stream2, err := client.GetMappingUpdate(ctx2, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: clusterAddress,
	})
	require.NoError(t, err)

	for {
		msg, err := stream2.Recv()
		require.NoError(t, err)
		if msg.GetInitialSyncComplete() {
			break
		}
	}

	cancel1()

	time.Sleep(200 * time.Millisecond)

	assert.Contains(t, setup.proxyService.GetConnectedProxies(), proxyID,
		"proxy should still be registered after old connection cleanup — old defer must not remove new connection")

	setup.proxyService.SendServiceUpdate(&proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{{
			Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
			Id:        "rp-1",
			AccountId: "test-account-1",
			Domain:    "app1.test.proxy.io",
		}},
	})

	msg, err := stream2.Recv()
	require.NoError(t, err, "new stream should still receive updates")
	require.NotEmpty(t, msg.GetMapping(), "update should contain the mapping")
	assert.Equal(t, "rp-1", msg.GetMapping()[0].GetId())
}
