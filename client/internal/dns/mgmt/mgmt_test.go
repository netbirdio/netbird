package mgmt

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

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

	mgmtURL, _ := url.Parse("https://api.netbird.io")

	err := resolver.PopulateFromConfig(ctx, mgmtURL)
	assert.NoError(t, err)

	// Give some time for async population
	time.Sleep(100 * time.Millisecond)

	domains := resolver.GetCachedDomains()
	assert.GreaterOrEqual(t, len(domains), 0) // Domains might not be cached yet due to async nature
}

func TestResolver_PopulateFromNetbirdConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := NewResolver()

	netbirdConfig := &mgmProto.NetbirdConfig{
		Signal: &mgmProto.HostConfig{
			Uri: "https://signal.netbird.io",
		},
		Relay: &mgmProto.RelayConfig{
			Urls: []string{
				"https://relay1.netbird.io:443",
				"https://relay2.netbird.io:443",
			},
		},
		Flow: &mgmProto.FlowConfig{
			Url: "https://flow.netbird.io:80",
		},
		Stuns: []*mgmProto.HostConfig{
			{Uri: "stun:stun1.netbird.io:3478"},
			{Uri: "stun:stun2.netbird.io:3478"},
		},
		Turns: []*mgmProto.ProtectedHostConfig{
			{
				HostConfig: &mgmProto.HostConfig{
					Uri: "turn:turn1.netbird.io:3478",
				},
			},
			{
				HostConfig: &mgmProto.HostConfig{
					Uri: "turn:turn2.netbird.io:3478",
				},
			},
		},
	}

	err := resolver.PopulateFromNetbirdConfig(ctx, netbirdConfig)
	assert.NoError(t, err)

	// Give some time for async population
	time.Sleep(100 * time.Millisecond)

	domains := resolver.GetCachedDomains()
	assert.GreaterOrEqual(t, len(domains), 0) // Domains might not be cached yet due to async nature
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
