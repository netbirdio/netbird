package grpc

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// registerFakeProxy adds a fake proxy connection to the server's internal maps
// and returns the channel where messages will be received.
func registerFakeProxy(s *ProxyServiceServer, proxyID, clusterAddr string) chan *proto.GetMappingUpdateResponse {
	ch := make(chan *proto.GetMappingUpdateResponse, 10)
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

func drainChannel(ch chan *proto.GetMappingUpdateResponse) *proto.GetMappingUpdateResponse {
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
		tokenStore: tokenStore,
	}

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

	update := &proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{mapping},
	}

	s.SendServiceUpdateToCluster(update, cluster)

	tokens := make([]string, numProxies)
	for i, ch := range channels {
		resp := drainChannel(ch)
		require.NotNil(t, resp, "proxy %d should receive a message", i)
		require.Len(t, resp.Mapping, 1, "proxy %d should receive exactly one mapping", i)
		msg := resp.Mapping[0]
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
	tokenStore := NewOneTimeTokenStore(time.Hour)
	defer tokenStore.Close()

	s := &ProxyServiceServer{
		tokenStore: tokenStore,
	}

	const cluster = "proxy.example.com"
	ch1 := registerFakeProxy(s, "proxy-a", cluster)
	ch2 := registerFakeProxy(s, "proxy-b", cluster)

	mapping := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
		Id:        "service-1",
		AccountId: "account-1",
		Domain:    "test.example.com",
	}

	update := &proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{mapping},
	}

	s.SendServiceUpdateToCluster(update, cluster)

	resp1 := drainChannel(ch1)
	resp2 := drainChannel(ch2)
	require.NotNil(t, resp1)
	require.NotNil(t, resp2)
	require.Len(t, resp1.Mapping, 1)
	require.Len(t, resp2.Mapping, 1)

	// Delete operations should not generate tokens
	assert.Empty(t, resp1.Mapping[0].AuthToken)
	assert.Empty(t, resp2.Mapping[0].AuthToken)

	// No tokens should have been created
	assert.Equal(t, 0, tokenStore.GetTokenCount())
}

func TestSendServiceUpdate_UniqueTokensPerProxy(t *testing.T) {
	tokenStore := NewOneTimeTokenStore(time.Hour)
	defer tokenStore.Close()

	s := &ProxyServiceServer{
		tokenStore: tokenStore,
	}

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

	resp1 := drainChannel(ch1)
	resp2 := drainChannel(ch2)
	require.NotNil(t, resp1)
	require.NotNil(t, resp2)
	require.Len(t, resp1.Mapping, 1)
	require.Len(t, resp2.Mapping, 1)

	msg1 := resp1.Mapping[0]
	msg2 := resp2.Mapping[0]

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
	s := &ProxyServiceServer{
		oidcConfig: ProxyOIDCConfig{
			HMACKey: []byte("test-hmac-key"),
		},
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
	s := &ProxyServiceServer{
		oidcConfig: ProxyOIDCConfig{
			HMACKey: []byte("test-hmac-key"),
		},
	}

	// Old format had only 2 parts: base64(url)|hmac
	s.pkceVerifiers.Store("base64url|hmac", pkceEntry{verifier: "test", createdAt: time.Now()})

	_, _, err := s.ValidateState("base64url|hmac")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state format")
}

func TestValidateState_RejectsInvalidHMAC(t *testing.T) {
	s := &ProxyServiceServer{
		oidcConfig: ProxyOIDCConfig{
			HMACKey: []byte("test-hmac-key"),
		},
	}

	// Store with tampered HMAC
	s.pkceVerifiers.Store("dGVzdA==|nonce|wrong-hmac", pkceEntry{verifier: "test", createdAt: time.Now()})

	_, _, err := s.ValidateState("dGVzdA==|nonce|wrong-hmac")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state signature")
}
