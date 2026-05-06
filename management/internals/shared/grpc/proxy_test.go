package grpc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	cachestore "github.com/eko/gocache/lib/v4/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func testCacheStore(t *testing.T) cachestore.StoreInterface {
	t.Helper()
	s, err := nbcache.NewStore(context.Background(), 30*time.Minute, 10*time.Minute, 100)
	require.NoError(t, err)
	return s
}

type testProxyController struct {
	mu             sync.Mutex
	clusterProxies map[string]map[string]struct{}
}

func newTestProxyController() *testProxyController {
	return &testProxyController{
		clusterProxies: make(map[string]map[string]struct{}),
	}
}

func (c *testProxyController) SendServiceUpdateToCluster(_ context.Context, _ string, _ *proto.ProxyMapping, _ string) {
}

func (c *testProxyController) GetOIDCValidationConfig() proxy.OIDCValidationConfig {
	return proxy.OIDCValidationConfig{}
}

func (c *testProxyController) RegisterProxyToCluster(_ context.Context, clusterAddr, proxyID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.clusterProxies[clusterAddr]; !ok {
		c.clusterProxies[clusterAddr] = make(map[string]struct{})
	}
	c.clusterProxies[clusterAddr][proxyID] = struct{}{}
	return nil
}

func (c *testProxyController) UnregisterProxyFromCluster(_ context.Context, clusterAddr, proxyID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if proxies, ok := c.clusterProxies[clusterAddr]; ok {
		delete(proxies, proxyID)
	}
	return nil
}

func (c *testProxyController) GetProxiesForCluster(clusterAddr string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	proxies, ok := c.clusterProxies[clusterAddr]
	if !ok {
		return nil
	}
	result := make([]string, 0, len(proxies))
	for id := range proxies {
		result = append(result, id)
	}
	return result
}

// registerFakeProxy adds a fake proxy connection to the server's internal maps
// and returns the channel where messages will be received.
func registerFakeProxy(s *ProxyServiceServer, proxyID, clusterAddr string) chan *proto.GetMappingUpdateResponse {
	return registerFakeProxyWithCaps(s, proxyID, clusterAddr, nil)
}

// registerFakeProxyWithCaps adds a fake proxy connection with explicit capabilities.
func registerFakeProxyWithCaps(s *ProxyServiceServer, proxyID, clusterAddr string, caps *proto.ProxyCapabilities) chan *proto.GetMappingUpdateResponse {
	ch := make(chan *proto.GetMappingUpdateResponse, 10)
	ctx, cancel := context.WithCancel(context.Background())
	conn := &proxyConnection{
		proxyID:      proxyID,
		address:      clusterAddr,
		capabilities: caps,
		sendChan:     ch,
		ctx:          ctx,
		cancel:       cancel,
	}
	s.connectedProxies.Store(proxyID, conn)

	_ = s.proxyController.RegisterProxyToCluster(context.Background(), clusterAddr, proxyID)

	return ch
}

// drainMapping drains a single ProxyMapping from the channel.
func drainMapping(ch chan *proto.GetMappingUpdateResponse) *proto.ProxyMapping {
	select {
	case resp := <-ch:
		if len(resp.Mapping) > 0 {
			return resp.Mapping[0]
		}
		return nil
	case <-time.After(time.Second):
		return nil
	}
}

// drainEmpty checks if a channel has no message within timeout.
func drainEmpty(ch chan *proto.GetMappingUpdateResponse) bool {
	select {
	case <-ch:
		return false
	case <-time.After(100 * time.Millisecond):
		return true
	}
}

func TestSendServiceUpdateToCluster_UniqueTokensPerProxy(t *testing.T) {
	ctx := context.Background()
	tokenStore := NewOneTimeTokenStore(ctx, testCacheStore(t))
	pkceStore := NewPKCEVerifierStore(ctx, testCacheStore(t))

	s := &ProxyServiceServer{
		tokenStore:        tokenStore,
		pkceVerifierStore: pkceStore,
	}
	s.SetProxyController(newTestProxyController())

	const cluster = "proxy.example.com"
	const numProxies = 3

	channels := make([]chan *proto.GetMappingUpdateResponse, numProxies)
	for i := range numProxies {
		id := "proxy-" + string(rune('a'+i))
		channels[i] = registerFakeProxy(s, id, cluster)
	}

	mapping := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-1",
		AccountId: "account-1",
		Domain:    "test.example.com",
		Path: []*proto.PathMapping{
			{Path: "/", Target: "http://10.0.0.1:8080/"},
		},
	}

	s.SendServiceUpdateToCluster(context.Background(), mapping, cluster)

	tokens := make([]string, numProxies)
	for i, ch := range channels {
		msg := drainMapping(ch)
		require.NotNil(t, msg, "proxy %d should receive a message", i)
		assert.Equal(t, mapping.Domain, msg.Domain)
		assert.Equal(t, mapping.Id, msg.Id)
		assert.NotEmpty(t, msg.AuthToken, "proxy %d should have a non-empty token", i)
		tokens[i] = msg.AuthToken
	}

	// All tokens must be unique
	tokenSet := make(map[string]struct{})
	for i, tok := range tokens {
		_, exists := tokenSet[tok]
		assert.False(t, exists, "proxy %d got duplicate token", i)
		tokenSet[tok] = struct{}{}
	}

	// Each token must be independently consumable
	for i, tok := range tokens {
		err := tokenStore.ValidateAndConsume(tok, "account-1", "service-1")
		assert.NoError(t, err, "proxy %d token should validate successfully", i)
	}
}

func TestSendServiceUpdateToCluster_DeleteNoToken(t *testing.T) {
	ctx := context.Background()
	tokenStore := NewOneTimeTokenStore(ctx, testCacheStore(t))
	pkceStore := NewPKCEVerifierStore(ctx, testCacheStore(t))

	s := &ProxyServiceServer{
		tokenStore:        tokenStore,
		pkceVerifierStore: pkceStore,
	}
	s.SetProxyController(newTestProxyController())

	const cluster = "proxy.example.com"
	ch1 := registerFakeProxy(s, "proxy-a", cluster)
	ch2 := registerFakeProxy(s, "proxy-b", cluster)

	mapping := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
		Id:        "service-1",
		AccountId: "account-1",
		Domain:    "test.example.com",
	}

	s.SendServiceUpdateToCluster(context.Background(), mapping, cluster)

	msg1 := drainMapping(ch1)
	msg2 := drainMapping(ch2)
	require.NotNil(t, msg1)
	require.NotNil(t, msg2)

	// Delete operations should not generate tokens
	assert.Empty(t, msg1.AuthToken)
	assert.Empty(t, msg2.AuthToken)
}

func TestSendServiceUpdate_UniqueTokensPerProxy(t *testing.T) {
	ctx := context.Background()
	tokenStore := NewOneTimeTokenStore(ctx, testCacheStore(t))
	pkceStore := NewPKCEVerifierStore(ctx, testCacheStore(t))

	s := &ProxyServiceServer{
		tokenStore:        tokenStore,
		pkceVerifierStore: pkceStore,
	}
	s.SetProxyController(newTestProxyController())

	// Register proxies in different clusters (SendServiceUpdate broadcasts to all)
	ch1 := registerFakeProxy(s, "proxy-a", "cluster-a")
	ch2 := registerFakeProxy(s, "proxy-b", "cluster-b")

	mapping := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-1",
		AccountId: "account-1",
		Domain:    "test.example.com",
	}

	update := &proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{mapping},
	}

	s.SendServiceUpdate(update)

	msg1 := drainMapping(ch1)
	msg2 := drainMapping(ch2)
	require.NotNil(t, msg1)
	require.NotNil(t, msg2)

	assert.NotEmpty(t, msg1.AuthToken)
	assert.NotEmpty(t, msg2.AuthToken)
	assert.NotEqual(t, msg1.AuthToken, msg2.AuthToken, "tokens must be unique per proxy")

	// Both tokens should validate
	assert.NoError(t, tokenStore.ValidateAndConsume(msg1.AuthToken, "account-1", "service-1"))
	assert.NoError(t, tokenStore.ValidateAndConsume(msg2.AuthToken, "account-1", "service-1"))
}

// generateState creates a state using the same format as GetOIDCURL.
func generateState(s *ProxyServiceServer, redirectURL string) string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	nonceB64 := base64.URLEncoding.EncodeToString(nonce)

	payload := redirectURL + "|" + nonceB64
	hmacSum := s.generateHMAC(payload)
	return base64.URLEncoding.EncodeToString([]byte(redirectURL)) + "|" + nonceB64 + "|" + hmacSum
}

func TestOAuthState_NeverTheSame(t *testing.T) {
	ctx := context.Background()
	pkceStore := NewPKCEVerifierStore(ctx, testCacheStore(t))

	s := &ProxyServiceServer{
		oidcConfig: ProxyOIDCConfig{
			HMACKey: []byte("test-hmac-key"),
		},
		pkceVerifierStore: pkceStore,
	}

	redirectURL := "https://app.example.com/callback"

	// Generate 100 states for the same redirect URL
	states := make(map[string]bool)
	for i := 0; i < 100; i++ {
		state := generateState(s, redirectURL)

		// State must have 3 parts: base64(url)|nonce|hmac
		parts := strings.Split(state, "|")
		require.Equal(t, 3, len(parts), "state must have 3 parts")

		// State must be unique
		require.False(t, states[state], "state %d is a duplicate", i)
		states[state] = true
	}
}

func TestValidateState_RejectsOldTwoPartFormat(t *testing.T) {
	ctx := context.Background()
	pkceStore := NewPKCEVerifierStore(ctx, testCacheStore(t))

	s := &ProxyServiceServer{
		oidcConfig: ProxyOIDCConfig{
			HMACKey: []byte("test-hmac-key"),
		},
		pkceVerifierStore: pkceStore,
	}

	// Old format had only 2 parts: base64(url)|hmac
	err := s.pkceVerifierStore.Store("base64url|hmac", "test", 10*time.Minute)
	require.NoError(t, err)

	_, _, err = s.ValidateState("base64url|hmac")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state format")
}

func TestValidateState_RejectsInvalidHMAC(t *testing.T) {
	ctx := context.Background()
	pkceStore := NewPKCEVerifierStore(ctx, testCacheStore(t))

	s := &ProxyServiceServer{
		oidcConfig: ProxyOIDCConfig{
			HMACKey: []byte("test-hmac-key"),
		},
		pkceVerifierStore: pkceStore,
	}

	// Store with tampered HMAC
	err := s.pkceVerifierStore.Store("dGVzdA==|nonce|wrong-hmac", "test", 10*time.Minute)
	require.NoError(t, err)

	_, _, err = s.ValidateState("dGVzdA==|nonce|wrong-hmac")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state signature")
}

func TestSendServiceUpdateToCluster_FiltersOnCapability(t *testing.T) {
	tokenStore := NewOneTimeTokenStore(context.Background(), testCacheStore(t))

	s := &ProxyServiceServer{
		tokenStore: tokenStore,
	}
	s.SetProxyController(newTestProxyController())

	const cluster = "proxy.example.com"

	// Modern proxy reports capabilities.
	chModern := registerFakeProxyWithCaps(s, "proxy-modern", cluster, &proto.ProxyCapabilities{SupportsCustomPorts: ptr(true)})
	// Legacy proxy never reported capabilities (nil).
	chLegacy := registerFakeProxy(s, "proxy-legacy", cluster)

	ctx := context.Background()

	// TLS passthrough with custom port: all proxies receive it (SNI routing).
	tlsMapping := &proto.ProxyMapping{
		Type:       proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:         "service-tls",
		AccountId:  "account-1",
		Domain:     "db.example.com",
		Mode:       "tls",
		ListenPort: 8443,
		Path:       []*proto.PathMapping{{Target: "10.0.0.5:5432"}},
	}

	s.SendServiceUpdateToCluster(ctx, tlsMapping, cluster)

	assert.NotNil(t, drainMapping(chModern), "modern proxy should receive TLS mapping")
	assert.NotNil(t, drainMapping(chLegacy), "legacy proxy should receive TLS mapping (SNI works on all)")

	// TCP mapping with custom port: only modern proxy receives it.
	tcpMapping := &proto.ProxyMapping{
		Type:       proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:         "service-tcp",
		AccountId:  "account-1",
		Domain:     "db.example.com",
		Mode:       "tcp",
		ListenPort: 5432,
		Path:       []*proto.PathMapping{{Target: "10.0.0.5:5432"}},
	}

	s.SendServiceUpdateToCluster(ctx, tcpMapping, cluster)

	assert.NotNil(t, drainMapping(chModern), "modern proxy should receive TCP custom-port mapping")
	assert.Nil(t, drainMapping(chLegacy), "legacy proxy should NOT receive TCP custom-port mapping")

	// HTTP mapping (no listen port): both receive it.
	httpMapping := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-http",
		AccountId: "account-1",
		Domain:    "app.example.com",
		Path:      []*proto.PathMapping{{Path: "/", Target: "http://10.0.0.1:80"}},
	}

	s.SendServiceUpdateToCluster(ctx, httpMapping, cluster)

	assert.NotNil(t, drainMapping(chModern), "modern proxy should receive HTTP mapping")
	assert.NotNil(t, drainMapping(chLegacy), "legacy proxy should receive HTTP mapping")

	// Proxy that reports SupportsCustomPorts=false still receives custom-port
	// mappings because it understands the protocol (it's new enough).
	chNewNoCustom := registerFakeProxyWithCaps(s, "proxy-new-no-custom", cluster, &proto.ProxyCapabilities{SupportsCustomPorts: ptr(false)})

	s.SendServiceUpdateToCluster(ctx, tcpMapping, cluster)

	assert.NotNil(t, drainMapping(chNewNoCustom), "new proxy with SupportsCustomPorts=false should still receive mapping")
}

func TestSendServiceUpdateToCluster_TLSNotFiltered(t *testing.T) {
	tokenStore := NewOneTimeTokenStore(context.Background(), testCacheStore(t))

	s := &ProxyServiceServer{
		tokenStore: tokenStore,
	}
	s.SetProxyController(newTestProxyController())

	const cluster = "proxy.example.com"

	// Legacy proxy (no capabilities) still receives TLS since it uses SNI.
	chLegacy := registerFakeProxy(s, "proxy-legacy", cluster)

	tlsMapping := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-tls",
		AccountId: "account-1",
		Domain:    "db.example.com",
		Mode:      "tls",
		Path:      []*proto.PathMapping{{Target: "10.0.0.5:5432"}},
	}

	s.SendServiceUpdateToCluster(context.Background(), tlsMapping, cluster)

	msg := drainMapping(chLegacy)
	assert.NotNil(t, msg, "legacy proxy should receive TLS mapping (SNI works without custom port support)")
}

// TestServiceModifyNotifications exercises every possible modification
// scenario for an existing service, verifying the correct update types
// reach the correct clusters.
func TestServiceModifyNotifications(t *testing.T) {
	tokenStore := NewOneTimeTokenStore(context.Background(), testCacheStore(t))

	newServer := func() (*ProxyServiceServer, map[string]chan *proto.GetMappingUpdateResponse) {
		s := &ProxyServiceServer{
			tokenStore: tokenStore,
		}
		s.SetProxyController(newTestProxyController())
		chs := map[string]chan *proto.GetMappingUpdateResponse{
			"cluster-a": registerFakeProxyWithCaps(s, "proxy-a", "cluster-a", &proto.ProxyCapabilities{SupportsCustomPorts: ptr(true)}),
			"cluster-b": registerFakeProxyWithCaps(s, "proxy-b", "cluster-b", &proto.ProxyCapabilities{SupportsCustomPorts: ptr(true)}),
		}
		return s, chs
	}

	httpMapping := func(updateType proto.ProxyMappingUpdateType) *proto.ProxyMapping {
		return &proto.ProxyMapping{
			Type:      updateType,
			Id:        "svc-1",
			AccountId: "acct-1",
			Domain:    "app.example.com",
			Path:      []*proto.PathMapping{{Path: "/", Target: "http://10.0.0.1:8080"}},
		}
	}

	tlsOnlyMapping := func(updateType proto.ProxyMappingUpdateType) *proto.ProxyMapping {
		return &proto.ProxyMapping{
			Type:       updateType,
			Id:         "svc-1",
			AccountId:  "acct-1",
			Domain:     "app.example.com",
			Mode:       "tls",
			ListenPort: 8443,
			Path:       []*proto.PathMapping{{Target: "10.0.0.1:443"}},
		}
	}

	ctx := context.Background()

	t.Run("targets changed sends MODIFIED to same cluster", func(t *testing.T) {
		s, chs := newServer()
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED), "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg, "cluster-a should receive update")
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED, msg.Type)
		assert.NotEmpty(t, msg.AuthToken, "MODIFIED should include token")
		assert.True(t, drainEmpty(chs["cluster-b"]), "cluster-b should not receive update")
	})

	t.Run("auth config changed sends MODIFIED", func(t *testing.T) {
		s, chs := newServer()
		mapping := httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED)
		mapping.Auth = &proto.Authentication{Password: true, Pin: true}
		s.SendServiceUpdateToCluster(ctx, mapping, "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED, msg.Type)
		assert.True(t, msg.Auth.Password)
		assert.True(t, msg.Auth.Pin)
	})

	t.Run("HTTP to TLS transition sends MODIFIED with TLS config", func(t *testing.T) {
		s, chs := newServer()
		s.SendServiceUpdateToCluster(ctx, tlsOnlyMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED), "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED, msg.Type)
		assert.Equal(t, "tls", msg.Mode, "mode should be tls")
		assert.Equal(t, int32(8443), msg.ListenPort)
		assert.Len(t, msg.Path, 1, "should have one path entry with target address")
		assert.Equal(t, "10.0.0.1:443", msg.Path[0].Target)
	})

	t.Run("TLS to HTTP transition sends MODIFIED without TLS", func(t *testing.T) {
		s, chs := newServer()
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED), "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED, msg.Type)
		assert.Empty(t, msg.Mode, "mode should be empty for HTTP")
		assert.True(t, len(msg.Path) > 0)
	})

	t.Run("TLS port changed sends MODIFIED with new port", func(t *testing.T) {
		s, chs := newServer()
		mapping := tlsOnlyMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED)
		mapping.ListenPort = 9443
		s.SendServiceUpdateToCluster(ctx, mapping, "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		assert.Equal(t, int32(9443), msg.ListenPort)
	})

	t.Run("disable sends REMOVED to cluster", func(t *testing.T) {
		s, chs := newServer()
		// Manager sends Delete when service is disabled
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED), "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, msg.Type)
		assert.Empty(t, msg.AuthToken, "DELETE should not have token")
	})

	t.Run("enable sends CREATED to cluster", func(t *testing.T) {
		s, chs := newServer()
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED), "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, msg.Type)
		assert.NotEmpty(t, msg.AuthToken)
	})

	t.Run("domain change with cluster change sends DELETE to old CREATE to new", func(t *testing.T) {
		s, chs := newServer()
		// This is the pattern the manager produces:
		// 1. DELETE on old cluster
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED), "cluster-a")
		// 2. CREATE on new cluster
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED), "cluster-b")

		msgA := drainMapping(chs["cluster-a"])
		require.NotNil(t, msgA, "old cluster should receive DELETE")
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, msgA.Type)

		msgB := drainMapping(chs["cluster-b"])
		require.NotNil(t, msgB, "new cluster should receive CREATE")
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, msgB.Type)
		assert.NotEmpty(t, msgB.AuthToken)
	})

	t.Run("domain change same cluster sends DELETE then CREATE", func(t *testing.T) {
		s, chs := newServer()
		// Domain changes within same cluster: manager sends DELETE (old domain) + CREATE (new domain).
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED), "cluster-a")
		s.SendServiceUpdateToCluster(ctx, httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED), "cluster-a")

		msgDel := drainMapping(chs["cluster-a"])
		require.NotNil(t, msgDel, "same cluster should receive DELETE")
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED, msgDel.Type)

		msgCreate := drainMapping(chs["cluster-a"])
		require.NotNil(t, msgCreate, "same cluster should receive CREATE")
		assert.Equal(t, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED, msgCreate.Type)
		assert.NotEmpty(t, msgCreate.AuthToken)
	})

	t.Run("TLS passthrough sent to all proxies", func(t *testing.T) {
		s := &ProxyServiceServer{
			tokenStore: tokenStore,
		}
		s.SetProxyController(newTestProxyController())
		const cluster = "proxy.example.com"
		chModern := registerFakeProxyWithCaps(s, "modern", cluster, &proto.ProxyCapabilities{SupportsCustomPorts: ptr(true)})
		chLegacy := registerFakeProxy(s, "legacy", cluster)

		// TLS passthrough works on all proxies regardless of custom port support
		s.SendServiceUpdateToCluster(ctx, tlsOnlyMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED), cluster)

		msgModern := drainMapping(chModern)
		require.NotNil(t, msgModern, "modern proxy receives TLS update")
		assert.Equal(t, "tls", msgModern.Mode)

		msgLegacy := drainMapping(chLegacy)
		assert.NotNil(t, msgLegacy, "legacy proxy should also receive TLS passthrough")
	})

	t.Run("TLS on default port NOT filtered for legacy proxy", func(t *testing.T) {
		s := &ProxyServiceServer{
			tokenStore: tokenStore,
		}
		s.SetProxyController(newTestProxyController())
		const cluster = "proxy.example.com"
		chLegacy := registerFakeProxy(s, "legacy", cluster)

		mapping := tlsOnlyMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED)
		mapping.ListenPort = 0 // default port
		s.SendServiceUpdateToCluster(ctx, mapping, cluster)

		msgLegacy := drainMapping(chLegacy)
		assert.NotNil(t, msgLegacy, "legacy proxy should receive TLS on default port")
	})

	t.Run("passthrough and rewrite flags propagated", func(t *testing.T) {
		s, chs := newServer()
		mapping := httpMapping(proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED)
		mapping.PassHostHeader = true
		mapping.RewriteRedirects = true
		s.SendServiceUpdateToCluster(ctx, mapping, "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		assert.True(t, msg.PassHostHeader)
		assert.True(t, msg.RewriteRedirects)
	})

	t.Run("multiple paths propagated in MODIFIED", func(t *testing.T) {
		s, chs := newServer()
		mapping := &proto.ProxyMapping{
			Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED,
			Id:        "svc-multi",
			AccountId: "acct-1",
			Domain:    "multi.example.com",
			Path: []*proto.PathMapping{
				{Path: "/", Target: "http://10.0.0.1:8080"},
				{Path: "/api", Target: "http://10.0.0.2:9090"},
				{Path: "/ws", Target: "http://10.0.0.3:3000"},
			},
		}
		s.SendServiceUpdateToCluster(ctx, mapping, "cluster-a")

		msg := drainMapping(chs["cluster-a"])
		require.NotNil(t, msg)
		require.Len(t, msg.Path, 3, "all paths should be present")
		assert.Equal(t, "/", msg.Path[0].Path)
		assert.Equal(t, "/api", msg.Path[1].Path)
		assert.Equal(t, "/ws", msg.Path[2].Path)
	})
}
