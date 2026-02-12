package grpc

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// registerFakeProxy adds a fake proxy connection to the server's internal maps
// and returns the channel where messages will be received.
func registerFakeProxy(s *ProxyServiceServer, proxyID, clusterAddr string) chan *proto.ProxyMapping {
	ch := make(chan *proto.ProxyMapping, 10)
	conn := &proxyConnection{
		proxyID:  proxyID,
		address:  clusterAddr,
		sendChan: ch,
	}
	s.connectedProxies.Store(proxyID, conn)

	proxySet, _ := s.clusterProxies.LoadOrStore(clusterAddr, &sync.Map{})
	proxySet.(*sync.Map).Store(proxyID, struct{}{})

	return ch
}

func drainChannel(ch chan *proto.ProxyMapping) *proto.ProxyMapping {
	select {
	case msg := <-ch:
		return msg
	case <-time.After(time.Second):
		return nil
	}
}

func TestSendServiceUpdateToCluster_UniqueTokensPerProxy(t *testing.T) {
	tokenStore := NewOneTimeTokenStore(time.Hour)
	defer tokenStore.Close()

	s := &ProxyServiceServer{
		tokenStore:  tokenStore,
		updatesChan: make(chan *proto.ProxyMapping, 100),
	}

	const cluster = "proxy.example.com"
	const numProxies = 3

	channels := make([]chan *proto.ProxyMapping, numProxies)
	for i := range numProxies {
		id := "proxy-" + string(rune('a'+i))
		channels[i] = registerFakeProxy(s, id, cluster)
	}

	update := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-1",
		AccountId: "account-1",
		Domain:    "test.example.com",
		Path: []*proto.PathMapping{
			{Path: "/", Target: "http://10.0.0.1:8080/"},
		},
	}

	s.SendServiceUpdateToCluster(update, cluster)

	tokens := make([]string, numProxies)
	for i, ch := range channels {
		msg := drainChannel(ch)
		require.NotNil(t, msg, "proxy %d should receive a message", i)
		assert.Equal(t, update.Domain, msg.Domain)
		assert.Equal(t, update.Id, msg.Id)
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
	tokenStore := NewOneTimeTokenStore(time.Hour)
	defer tokenStore.Close()

	s := &ProxyServiceServer{
		tokenStore:  tokenStore,
		updatesChan: make(chan *proto.ProxyMapping, 100),
	}

	const cluster = "proxy.example.com"
	ch1 := registerFakeProxy(s, "proxy-a", cluster)
	ch2 := registerFakeProxy(s, "proxy-b", cluster)

	update := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
		Id:        "service-1",
		AccountId: "account-1",
		Domain:    "test.example.com",
	}

	s.SendServiceUpdateToCluster(update, cluster)

	msg1 := drainChannel(ch1)
	msg2 := drainChannel(ch2)
	require.NotNil(t, msg1)
	require.NotNil(t, msg2)

	// Delete operations should not generate tokens
	assert.Empty(t, msg1.AuthToken)
	assert.Empty(t, msg2.AuthToken)

	// No tokens should have been created
	assert.Equal(t, 0, tokenStore.GetTokenCount())
}

func TestSendServiceUpdate_UniqueTokensPerProxy(t *testing.T) {
	tokenStore := NewOneTimeTokenStore(time.Hour)
	defer tokenStore.Close()

	s := &ProxyServiceServer{
		tokenStore:  tokenStore,
		updatesChan: make(chan *proto.ProxyMapping, 100),
	}

	// Register proxies in different clusters (SendServiceUpdate broadcasts to all)
	ch1 := registerFakeProxy(s, "proxy-a", "cluster-a")
	ch2 := registerFakeProxy(s, "proxy-b", "cluster-b")

	update := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-1",
		AccountId: "account-1",
		Domain:    "test.example.com",
	}

	s.SendServiceUpdate(update)

	msg1 := drainChannel(ch1)
	msg2 := drainChannel(ch2)
	require.NotNil(t, msg1)
	require.NotNil(t, msg2)

	assert.NotEmpty(t, msg1.AuthToken)
	assert.NotEmpty(t, msg2.AuthToken)
	assert.NotEqual(t, msg1.AuthToken, msg2.AuthToken, "tokens must be unique per proxy")

	// Both tokens should validate
	assert.NoError(t, tokenStore.ValidateAndConsume(msg1.AuthToken, "account-1", "service-1"))
	assert.NoError(t, tokenStore.ValidateAndConsume(msg2.AuthToken, "account-1", "service-1"))
}
