package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"

	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/users"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type byopTestSetup struct {
	store        store.Store
	proxyService *nbgrpc.ProxyServiceServer
	grpcServer   *grpc.Server
	grpcAddr     string
	cleanup      func()

	accountA        string
	accountB        string
	accountAToken   types.PlainProxyToken
	accountBToken   types.PlainProxyToken
	accountACluster string
	accountBCluster string
}

func setupBYOPIntegrationTest(t *testing.T) *byopTestSetup {
	t.Helper()
	ctx := context.Background()

	testStore, storeCleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)

	accountAID := "byop-account-a"
	accountBID := "byop-account-b"

	for _, acc := range []*types.Account{
		{Id: accountAID, Domain: "a.test.com", DomainCategory: "private", IsDomainPrimaryAccount: true, CreatedAt: time.Now()},
		{Id: accountBID, Domain: "b.test.com", DomainCategory: "private", IsDomainPrimaryAccount: true, CreatedAt: time.Now()},
	} {
		require.NoError(t, testStore.SaveAccount(ctx, acc))
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey := base64.StdEncoding.EncodeToString(pub)
	privKey := base64.StdEncoding.EncodeToString(priv)

	clusterA := "byop-a.proxy.test"
	clusterB := "byop-b.proxy.test"

	services := []*service.Service{
		{
			ID: "svc-a1", AccountID: accountAID, Name: "App A1",
			Domain: "app1." + clusterA, ProxyCluster: clusterA, Enabled: true,
			SessionPrivateKey: privKey, SessionPublicKey: pubKey,
			Targets: []*service.Target{{Path: strPtr("/"), Host: "10.0.0.1", Port: 8080, Protocol: "http", TargetId: "peer-a1", TargetType: "peer", Enabled: true}},
		},
		{
			ID: "svc-a2", AccountID: accountAID, Name: "App A2",
			Domain: "app2." + clusterA, ProxyCluster: clusterA, Enabled: true,
			SessionPrivateKey: privKey, SessionPublicKey: pubKey,
			Targets: []*service.Target{{Path: strPtr("/"), Host: "10.0.0.2", Port: 8080, Protocol: "http", TargetId: "peer-a2", TargetType: "peer", Enabled: true}},
		},
		{
			ID: "svc-b1", AccountID: accountBID, Name: "App B1",
			Domain: "app1." + clusterB, ProxyCluster: clusterB, Enabled: true,
			SessionPrivateKey: privKey, SessionPublicKey: pubKey,
			Targets: []*service.Target{{Path: strPtr("/"), Host: "10.0.0.3", Port: 8080, Protocol: "http", TargetId: "peer-b1", TargetType: "peer", Enabled: true}},
		},
	}
	for _, svc := range services {
		require.NoError(t, testStore.CreateService(ctx, svc))
	}

	tokenA, err := types.CreateNewProxyAccessToken("byop-token-a", 0, &accountAID, "admin-a")
	require.NoError(t, err)
	require.NoError(t, testStore.SaveProxyAccessToken(ctx, &tokenA.ProxyAccessToken))

	tokenB, err := types.CreateNewProxyAccessToken("byop-token-b", 0, &accountBID, "admin-b")
	require.NoError(t, err)
	require.NoError(t, testStore.SaveProxyAccessToken(ctx, &tokenB.ProxyAccessToken))

	cacheStore, err := nbcache.NewStore(ctx, 30*time.Minute, 10*time.Minute, 100)
	require.NoError(t, err)

	tokenStore := nbgrpc.NewOneTimeTokenStore(ctx, cacheStore)
	pkceStore := nbgrpc.NewPKCEVerifierStore(ctx, cacheStore)

	meter := noop.NewMeterProvider().Meter("test")
	realProxyManager, err := proxymanager.NewManager(testStore, meter)
	require.NoError(t, err)

	oidcConfig := nbgrpc.ProxyOIDCConfig{
		Issuer:   "https://fake-issuer.example.com",
		ClientID: "test-client",
		HMACKey:  []byte("test-hmac-key"),
	}

	usersManager := users.NewManager(testStore)

	proxyService := nbgrpc.NewProxyServiceServer(
		&testAccessLogManager{},
		tokenStore,
		pkceStore,
		oidcConfig,
		nil,
		usersManager,
		realProxyManager,
		nil,
	)

	svcMgr := &storeBackedServiceManager{store: testStore, tokenStore: tokenStore}
	proxyService.SetServiceManager(svcMgr)

	proxyController := &testProxyController{}
	proxyService.SetProxyController(proxyController)

	_, streamInterceptor, authClose := nbgrpc.NewProxyAuthInterceptors(testStore)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer(grpc.StreamInterceptor(streamInterceptor))
	proto.RegisterProxyServiceServer(grpcServer, proxyService)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("gRPC server error: %v", err)
		}
	}()

	return &byopTestSetup{
		store:        testStore,
		proxyService: proxyService,
		grpcServer:   grpcServer,
		grpcAddr:     lis.Addr().String(),
		cleanup: func() {
			grpcServer.GracefulStop()
			authClose()
			storeCleanup()
		},
		accountA:        accountAID,
		accountB:        accountBID,
		accountAToken:   tokenA.PlainToken,
		accountBToken:   tokenB.PlainToken,
		accountACluster: clusterA,
		accountBCluster: clusterB,
	}
}

func byopContext(ctx context.Context, token types.PlainProxyToken) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+string(token))
	return metadata.NewOutgoingContext(ctx, md)
}

func receiveBYOPMappings(t *testing.T, stream proto.ProxyService_GetMappingUpdateClient) []*proto.ProxyMapping {
	t.Helper()
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

func TestIntegration_BYOPProxy_ReceivesOnlyAccountServices(t *testing.T) {
	setup := setupBYOPIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(byopContext(context.Background(), setup.accountAToken), 5*time.Second)
	defer cancel()

	stream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId: "byop-proxy-a",
		Version: "test-v1",
		Address: setup.accountACluster,
	})
	require.NoError(t, err)

	mappings := receiveBYOPMappings(t, stream)

	assert.Len(t, mappings, 2, "BYOP proxy should receive only account A's 2 services")
	for _, m := range mappings {
		assert.Equal(t, setup.accountA, m.GetAccountId(), "all mappings should belong to account A")
		t.Logf("received mapping: id=%s domain=%s account=%s", m.GetId(), m.GetDomain(), m.GetAccountId())
	}

	ids := map[string]bool{}
	for _, m := range mappings {
		ids[m.GetId()] = true
	}
	assert.True(t, ids["svc-a1"], "should contain svc-a1")
	assert.True(t, ids["svc-a2"], "should contain svc-a2")
	assert.False(t, ids["svc-b1"], "should NOT contain account B's svc-b1")
}

func TestIntegration_BYOPProxy_AccountBReceivesOnlyItsServices(t *testing.T) {
	setup := setupBYOPIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(byopContext(context.Background(), setup.accountBToken), 5*time.Second)
	defer cancel()

	stream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId: "byop-proxy-b",
		Version: "test-v1",
		Address: setup.accountBCluster,
	})
	require.NoError(t, err)

	mappings := receiveBYOPMappings(t, stream)

	assert.Len(t, mappings, 1, "BYOP proxy B should receive only 1 service")
	assert.Equal(t, "svc-b1", mappings[0].GetId())
	assert.Equal(t, setup.accountB, mappings[0].GetAccountId())
}

func TestIntegration_BYOPProxy_MultiplePerAccount(t *testing.T) {
	setup := setupBYOPIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx1, cancel1 := context.WithTimeout(byopContext(context.Background(), setup.accountAToken), 5*time.Second)
	defer cancel1()

	stream1, err := client.GetMappingUpdate(ctx1, &proto.GetMappingUpdateRequest{
		ProxyId: "byop-proxy-a-first",
		Version: "test-v1",
		Address: setup.accountACluster,
	})
	require.NoError(t, err)

	mappings1 := receiveBYOPMappings(t, stream1)
	assert.Len(t, mappings1, 2, "first BYOP proxy should receive account A's 2 services")

	ctx2, cancel2 := context.WithTimeout(byopContext(context.Background(), setup.accountAToken), 5*time.Second)
	defer cancel2()

	stream2, err := client.GetMappingUpdate(ctx2, &proto.GetMappingUpdateRequest{
		ProxyId: "byop-proxy-a-second",
		Version: "test-v1",
		Address: setup.accountACluster,
	})
	require.NoError(t, err)

	mappings2 := receiveBYOPMappings(t, stream2)
	assert.Len(t, mappings2, 2, "second BYOP proxy from same account should also receive the 2 services")
	for _, m := range mappings2 {
		assert.Equal(t, setup.accountA, m.GetAccountId())
	}
}

func TestIntegration_BYOPProxy_ClusterAddressConflict(t *testing.T) {
	setup := setupBYOPIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx1, cancel1 := context.WithTimeout(byopContext(context.Background(), setup.accountAToken), 5*time.Second)
	defer cancel1()

	stream1, err := client.GetMappingUpdate(ctx1, &proto.GetMappingUpdateRequest{
		ProxyId: "byop-proxy-a-cluster",
		Version: "test-v1",
		Address: setup.accountACluster,
	})
	require.NoError(t, err)

	_ = receiveBYOPMappings(t, stream1)

	ctx2, cancel2 := context.WithTimeout(byopContext(context.Background(), setup.accountBToken), 5*time.Second)
	defer cancel2()

	stream2, err := client.GetMappingUpdate(ctx2, &proto.GetMappingUpdateRequest{
		ProxyId: "byop-proxy-b-conflict",
		Version: "test-v1",
		Address: setup.accountACluster,
	})
	require.NoError(t, err)

	_, err = stream2.Recv()
	require.Error(t, err)

	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code(), "cluster address conflict should return AlreadyExists")
	t.Logf("expected rejection: %s", st.Message())
}

func TestIntegration_BYOPProxy_SameProxyReconnects(t *testing.T) {
	setup := setupBYOPIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	proxyID := "byop-proxy-reconnect"

	ctx1, cancel1 := context.WithTimeout(byopContext(context.Background(), setup.accountAToken), 5*time.Second)
	stream1, err := client.GetMappingUpdate(ctx1, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: setup.accountACluster,
	})
	require.NoError(t, err)

	firstMappings := receiveBYOPMappings(t, stream1)
	cancel1()

	time.Sleep(200 * time.Millisecond)

	ctx2, cancel2 := context.WithTimeout(byopContext(context.Background(), setup.accountAToken), 5*time.Second)
	defer cancel2()

	stream2, err := client.GetMappingUpdate(ctx2, &proto.GetMappingUpdateRequest{
		ProxyId: proxyID,
		Version: "test-v1",
		Address: setup.accountACluster,
	})
	require.NoError(t, err)

	secondMappings := receiveBYOPMappings(t, stream2)

	assert.Equal(t, len(firstMappings), len(secondMappings), "reconnect should receive same mappings")

	firstIDs := map[string]bool{}
	for _, m := range firstMappings {
		firstIDs[m.GetId()] = true
	}
	for _, m := range secondMappings {
		assert.True(t, firstIDs[m.GetId()], "mapping %s should be present on reconnect", m.GetId())
	}
}

func TestIntegration_BYOPProxy_UnauthenticatedRejected(t *testing.T) {
	setup := setupBYOPIntegrationTest(t)
	defer setup.cleanup()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := proto.NewProxyServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId: "no-auth-proxy",
		Version: "test-v1",
		Address: "some.cluster.io",
	})
	require.NoError(t, err)

	_, err = stream.Recv()
	require.Error(t, err)

	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}
