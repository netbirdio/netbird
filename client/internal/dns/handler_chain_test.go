package dns_test

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
)

// MockHandler implements dns.Handler interface for testing
type MockHandler struct {
	mock.Mock
}

func (m *MockHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m.Called(w, r)
}

// TestHandlerChain_ServeDNS_Priorities tests that handlers are executed in priority order
func TestHandlerChain_ServeDNS_Priorities(t *testing.T) {
	chain := nbdns.NewHandlerChain()

	// Create mock handlers for different priorities
	defaultHandler := &MockHandler{}
	matchDomainHandler := &MockHandler{}
	dnsRouteHandler := &MockHandler{}

	// Setup handlers with different priorities
	chain.AddHandler("example.com.", defaultHandler, nbdns.PriorityDefault, nil)
	chain.AddHandler("example.com.", matchDomainHandler, nbdns.PriorityMatchDomain, nil)
	chain.AddHandler("example.com.", dnsRouteHandler, nbdns.PriorityDNSRoute, nil)

	// Create test request
	r := new(dns.Msg)
	r.SetQuestion("example.com.", dns.TypeA)

	// Create test writer
	w := &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}

	// Setup expectations - only highest priority handler should be called
	dnsRouteHandler.On("ServeDNS", mock.Anything, r).Once()
	matchDomainHandler.On("ServeDNS", mock.Anything, r).Maybe()
	defaultHandler.On("ServeDNS", mock.Anything, r).Maybe()

	// Execute
	chain.ServeDNS(w, r)

	// Verify all expectations were met
	dnsRouteHandler.AssertExpectations(t)
	matchDomainHandler.AssertExpectations(t)
	defaultHandler.AssertExpectations(t)
}

// TestHandlerChain_ServeDNS_DomainMatching tests various domain matching scenarios
func TestHandlerChain_ServeDNS_DomainMatching(t *testing.T) {
	tests := []struct {
		name          string
		handlerDomain string
		queryDomain   string
		isWildcard    bool
		shouldMatch   bool
	}{
		{
			name:          "exact match",
			handlerDomain: "example.com.",
			queryDomain:   "example.com.",
			isWildcard:    false,
			shouldMatch:   true,
		},
		{
			name:          "subdomain with non-wildcard",
			handlerDomain: "example.com.",
			queryDomain:   "sub.example.com.",
			isWildcard:    false,
			shouldMatch:   true,
		},
		{
			name:          "wildcard match",
			handlerDomain: "*.example.com.",
			queryDomain:   "sub.example.com.",
			isWildcard:    true,
			shouldMatch:   true,
		},
		{
			name:          "wildcard no match on apex",
			handlerDomain: "*.example.com.",
			queryDomain:   "example.com.",
			isWildcard:    true,
			shouldMatch:   false,
		},
		{
			name:          "root zone match",
			handlerDomain: ".",
			queryDomain:   "anything.com.",
			isWildcard:    false,
			shouldMatch:   true,
		},
		{
			name:          "no match different domain",
			handlerDomain: "example.com.",
			queryDomain:   "example.org.",
			isWildcard:    false,
			shouldMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := nbdns.NewHandlerChain()
			mockHandler := &MockHandler{}

			pattern := tt.handlerDomain
			if tt.isWildcard {
				pattern = "*." + tt.handlerDomain[2:] // Remove the first two chars if it's a wildcard
			}

			chain.AddHandler(pattern, mockHandler, nbdns.PriorityDefault, nil)

			r := new(dns.Msg)
			r.SetQuestion(tt.queryDomain, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}

			if tt.shouldMatch {
				mockHandler.On("ServeDNS", mock.Anything, r).Once()
			}

			chain.ServeDNS(w, r)
			mockHandler.AssertExpectations(t)
		})
	}
}

// TestHandlerChain_ServeDNS_OverlappingDomains tests behavior with overlapping domain patterns
func TestHandlerChain_ServeDNS_OverlappingDomains(t *testing.T) {
	tests := []struct {
		name     string
		handlers []struct {
			pattern  string
			priority int
		}
		queryDomain     string
		expectedCalls   int
		expectedHandler int // index of the handler that should be called
	}{
		{
			name: "wildcard and exact same priority - exact should win",
			handlers: []struct {
				pattern  string
				priority int
			}{
				{pattern: "*.example.com.", priority: nbdns.PriorityDefault},
				{pattern: "example.com.", priority: nbdns.PriorityDefault},
			},
			queryDomain:     "example.com.",
			expectedCalls:   1,
			expectedHandler: 1, // exact match handler should be called
		},
		{
			name: "higher priority wildcard over lower priority exact",
			handlers: []struct {
				pattern  string
				priority int
			}{
				{pattern: "example.com.", priority: nbdns.PriorityDefault},
				{pattern: "*.example.com.", priority: nbdns.PriorityDNSRoute},
			},
			queryDomain:     "test.example.com.",
			expectedCalls:   1,
			expectedHandler: 1, // higher priority wildcard handler should be called
		},
		{
			name: "multiple wildcards different priorities",
			handlers: []struct {
				pattern  string
				priority int
			}{
				{pattern: "*.example.com.", priority: nbdns.PriorityDefault},
				{pattern: "*.example.com.", priority: nbdns.PriorityMatchDomain},
				{pattern: "*.example.com.", priority: nbdns.PriorityDNSRoute},
			},
			queryDomain:     "test.example.com.",
			expectedCalls:   1,
			expectedHandler: 2, // highest priority handler should be called
		},
		{
			name: "subdomain with mix of patterns",
			handlers: []struct {
				pattern  string
				priority int
			}{
				{pattern: "*.example.com.", priority: nbdns.PriorityDefault},
				{pattern: "test.example.com.", priority: nbdns.PriorityMatchDomain},
				{pattern: "*.test.example.com.", priority: nbdns.PriorityDNSRoute},
			},
			queryDomain:     "sub.test.example.com.",
			expectedCalls:   1,
			expectedHandler: 2, // highest priority matching handler should be called
		},
		{
			name: "root zone with specific domain",
			handlers: []struct {
				pattern  string
				priority int
			}{
				{pattern: ".", priority: nbdns.PriorityDefault},
				{pattern: "example.com.", priority: nbdns.PriorityDNSRoute},
			},
			queryDomain:     "example.com.",
			expectedCalls:   1,
			expectedHandler: 1, // higher priority specific domain should win over root
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := nbdns.NewHandlerChain()
			var handlers []*MockHandler

			// Setup handlers and expectations
			for i := range tt.handlers {
				handler := &MockHandler{}
				handlers = append(handlers, handler)

				// Set expectation based on whether this handler should be called
				if i == tt.expectedHandler {
					handler.On("ServeDNS", mock.Anything, mock.Anything).Once()
				} else {
					handler.On("ServeDNS", mock.Anything, mock.Anything).Maybe()
				}

				chain.AddHandler(tt.handlers[i].pattern, handler, tt.handlers[i].priority, nil)
			}

			// Create and execute request
			r := new(dns.Msg)
			r.SetQuestion(tt.queryDomain, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}
			chain.ServeDNS(w, r)

			// Verify expectations
			for _, handler := range handlers {
				handler.AssertExpectations(t)
			}
		})
	}
}

// TestHandlerChain_ServeDNS_ChainContinuation tests the chain continuation functionality
func TestHandlerChain_ServeDNS_ChainContinuation(t *testing.T) {
	chain := nbdns.NewHandlerChain()

	// Create handlers
	handler1 := &MockHandler{}
	handler2 := &MockHandler{}
	handler3 := &MockHandler{}

	// Add handlers in priority order
	chain.AddHandler("example.com.", handler1, nbdns.PriorityDNSRoute, nil)
	chain.AddHandler("example.com.", handler2, nbdns.PriorityMatchDomain, nil)
	chain.AddHandler("example.com.", handler3, nbdns.PriorityDefault, nil)

	// Create test request
	r := new(dns.Msg)
	r.SetQuestion("example.com.", dns.TypeA)

	// Setup mock responses to simulate chain continuation
	handler1.On("ServeDNS", mock.Anything, r).Run(func(args mock.Arguments) {
		// First handler signals continue
		w := args.Get(0).(*nbdns.ResponseWriterChain)
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError)
		resp.MsgHdr.Zero = true // Signal to continue
		assert.NoError(t, w.WriteMsg(resp))
	}).Once()

	handler2.On("ServeDNS", mock.Anything, r).Run(func(args mock.Arguments) {
		// Second handler signals continue
		w := args.Get(0).(*nbdns.ResponseWriterChain)
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError)
		resp.MsgHdr.Zero = true
		assert.NoError(t, w.WriteMsg(resp))
	}).Once()

	handler3.On("ServeDNS", mock.Anything, r).Run(func(args mock.Arguments) {
		// Last handler responds normally
		w := args.Get(0).(*nbdns.ResponseWriterChain)
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeSuccess)
		assert.NoError(t, w.WriteMsg(resp))
	}).Once()

	// Execute
	w := &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}
	chain.ServeDNS(w, r)

	// Verify all handlers were called in order
	handler1.AssertExpectations(t)
	handler2.AssertExpectations(t)
	handler3.AssertExpectations(t)
}

// mockResponseWriter implements dns.ResponseWriter for testing
type mockResponseWriter struct {
	mock.Mock
}

func (m *mockResponseWriter) LocalAddr() net.Addr       { return nil }
func (m *mockResponseWriter) RemoteAddr() net.Addr      { return nil }
func (m *mockResponseWriter) WriteMsg(*dns.Msg) error   { return nil }
func (m *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (m *mockResponseWriter) Close() error              { return nil }
func (m *mockResponseWriter) TsigStatus() error         { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)       {}
func (m *mockResponseWriter) Hijack()                   {}
