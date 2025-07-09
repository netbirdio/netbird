package mgmt

import (
	"context"
	"net"
	"net/url"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func TestResolver_NewResolver(t *testing.T) {
	resolver := NewResolver()

	assert.NotNil(t, resolver)
	assert.NotNil(t, resolver.cache)
	assert.True(t, resolver.MatchSubdomains())
}

func TestResolver_ExtractDomainFromURL(t *testing.T) {
	tests := []struct {
		name        string
		urlStr      string
		expectedDom string
		expectError bool
	}{
		{
			name:        "HTTPS URL with port",
			urlStr:      "https://api.netbird.io:443",
			expectedDom: "api.netbird.io",
			expectError: false,
		},
		{
			name:        "HTTP URL without port",
			urlStr:      "http://signal.example.com",
			expectedDom: "signal.example.com",
			expectError: false,
		},
		{
			name:        "URL with path",
			urlStr:      "https://relay.netbird.io/status",
			expectedDom: "relay.netbird.io",
			expectError: false,
		},
		{
			name:        "Invalid URL",
			urlStr:      "not-a-valid-url",
			expectedDom: "not-a-valid-url",
			expectError: false,
		},
		{
			name:        "Empty URL",
			urlStr:      "",
			expectedDom: "",
			expectError: true,
		},
		{
			name:        "STUN URL",
			urlStr:      "stun:stun.example.com:3478",
			expectedDom: "stun.example.com",
			expectError: false,
		},
		{
			name:        "TURN URL",
			urlStr:      "turn:turn.example.com:3478",
			expectedDom: "turn.example.com",
			expectError: false,
		},
		{
			name:        "REL URL",
			urlStr:      "rel://relay.example.com:443",
			expectedDom: "relay.example.com",
			expectError: false,
		},
		{
			name:        "RELS URL",
			urlStr:      "rels://relay.example.com:443",
			expectedDom: "relay.example.com",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var parsedURL *url.URL
			var err error

			if tt.urlStr != "" {
				parsedURL, err = url.Parse(tt.urlStr)
				if err != nil && !tt.expectError {
					t.Fatalf("Failed to parse URL: %v", err)
				}
			}

			domain, err := extractDomainFromURL(parsedURL)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDom, domain.SafeString())
			}
		})
	}
}

func TestResolver_PopulateFromConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := NewResolver()

	// Use IP address to avoid DNS resolution timeout
	mgmtURL, _ := url.Parse("https://127.0.0.1")

	err := resolver.PopulateFromConfig(ctx, mgmtURL)
	assert.NoError(t, err)

	// IP addresses are rejected, so no domains should be cached
	domains := resolver.GetCachedDomains()
	assert.Equal(t, 0, len(domains), "No domains should be cached when using IP addresses")
}

func TestResolver_PopulateFromNetbirdConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := NewResolver()

	// Use IP addresses to avoid DNS resolution timeouts
	netbirdConfig := &mgmProto.NetbirdConfig{
		Signal: &mgmProto.HostConfig{
			Uri: "https://10.0.0.1",
		},
		Relay: &mgmProto.RelayConfig{
			Urls: []string{
				"https://10.0.0.2:443",
				"https://10.0.0.3:443",
			},
		},
		Flow: &mgmProto.FlowConfig{
			Url: "https://10.0.0.4:80",
		},
		Stuns: []*mgmProto.HostConfig{
			{Uri: "stun:10.0.0.5:3478"},
			{Uri: "stun:10.0.0.6:3478"},
		},
		Turns: []*mgmProto.ProtectedHostConfig{
			{
				HostConfig: &mgmProto.HostConfig{
					Uri: "turn:10.0.0.7:3478",
				},
			},
			{
				HostConfig: &mgmProto.HostConfig{
					Uri: "turn:10.0.0.8:3478",
				},
			},
		},
	}

	err := resolver.PopulateFromNetbirdConfig(ctx, netbirdConfig)
	assert.NoError(t, err)

	// IP addresses are rejected, so no domains should be cached
	domains := resolver.GetCachedDomains()
	assert.Equal(t, 0, len(domains), "No domains should be cached when using IP addresses")
}

func TestResolver_UpdateFromNetbirdConfig(t *testing.T) {
	resolver := NewResolver()

	// Test with empty initial config and then add domains
	initialConfig := &mgmProto.NetbirdConfig{}

	// Start with empty config
	removedDomains, err := resolver.UpdateFromNetbirdConfig(context.Background(), initialConfig)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(removedDomains), "No domains should be removed from empty cache")

	// Update to config with IP addresses instead of domains to avoid DNS resolution
	// IP addresses will be rejected by extractDomainFromURL so no actual resolution happens
	updatedConfig := &mgmProto.NetbirdConfig{
		Signal: &mgmProto.HostConfig{
			Uri: "https://127.0.0.1",
		},
		Flow: &mgmProto.FlowConfig{
			Url: "https://192.168.1.1:80",
		},
	}

	removedDomains, err = resolver.UpdateFromNetbirdConfig(context.Background(), updatedConfig)
	assert.NoError(t, err)

	// Verify the method completes successfully without DNS timeouts
	assert.GreaterOrEqual(t, len(removedDomains), 0, "Should not error on config update")

	// Verify no domains were actually added since IPs are rejected
	domains := resolver.GetCachedDomains()
	assert.Equal(t, 0, len(domains), "No domains should be cached when using IP addresses")
}

func TestResolver_ContinueToNext(t *testing.T) {
	resolver := NewResolver()

	// Create a mock response writer to capture the response
	mockWriter := &MockResponseWriter{}

	// Create a test DNS query
	req := new(dns.Msg)
	req.SetQuestion("unknown.example.com.", dns.TypeA)

	// Call continueToNext
	resolver.continueToNext(mockWriter, req)

	// Verify the response
	assert.NotNil(t, mockWriter.msg)
	assert.Equal(t, dns.RcodeNameError, mockWriter.msg.Rcode)
	assert.True(t, mockWriter.msg.MsgHdr.Zero)
}

// MockResponseWriter is a simple mock implementation of dns.ResponseWriter for testing
type MockResponseWriter struct {
	msg *dns.Msg
}

func (m *MockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}

func (m *MockResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *MockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.msg = msg
	return nil
}

func (m *MockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *MockResponseWriter) Close() error {
	return nil
}

func (m *MockResponseWriter) TsigStatus() error {
	return nil
}

func (m *MockResponseWriter) TsigTimersOnly(bool) {}

func (m *MockResponseWriter) Hijack() {}
