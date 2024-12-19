package dns_test

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
)

// TestHandlerChain_ServeDNS_Priorities tests that handlers are executed in priority order
func TestHandlerChain_ServeDNS_Priorities(t *testing.T) {
	chain := nbdns.NewHandlerChain()

	// Create mock handlers for different priorities
	defaultHandler := &nbdns.MockHandler{}
	matchDomainHandler := &nbdns.MockHandler{}
	dnsRouteHandler := &nbdns.MockHandler{}

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
		name            string
		handlerDomain   string
		queryDomain     string
		isWildcard      bool
		matchSubdomains bool
		shouldMatch     bool
	}{
		{
			name:            "exact match",
			handlerDomain:   "example.com.",
			queryDomain:     "example.com.",
			isWildcard:      false,
			matchSubdomains: false,
			shouldMatch:     true,
		},
		{
			name:            "subdomain with non-wildcard and MatchSubdomains true",
			handlerDomain:   "example.com.",
			queryDomain:     "sub.example.com.",
			isWildcard:      false,
			matchSubdomains: true,
			shouldMatch:     true,
		},
		{
			name:            "subdomain with non-wildcard and MatchSubdomains false",
			handlerDomain:   "example.com.",
			queryDomain:     "sub.example.com.",
			isWildcard:      false,
			matchSubdomains: false,
			shouldMatch:     false,
		},
		{
			name:            "wildcard match",
			handlerDomain:   "*.example.com.",
			queryDomain:     "sub.example.com.",
			isWildcard:      true,
			matchSubdomains: false,
			shouldMatch:     true,
		},
		{
			name:            "wildcard no match on apex",
			handlerDomain:   "*.example.com.",
			queryDomain:     "example.com.",
			isWildcard:      true,
			matchSubdomains: false,
			shouldMatch:     false,
		},
		{
			name:            "root zone match",
			handlerDomain:   ".",
			queryDomain:     "anything.com.",
			isWildcard:      false,
			matchSubdomains: false,
			shouldMatch:     true,
		},
		{
			name:            "no match different domain",
			handlerDomain:   "example.com.",
			queryDomain:     "example.org.",
			isWildcard:      false,
			matchSubdomains: false,
			shouldMatch:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := nbdns.NewHandlerChain()
			var handler dns.Handler

			if tt.matchSubdomains {
				mockSubHandler := &nbdns.MockSubdomainHandler{Subdomains: true}
				handler = mockSubHandler
				if tt.shouldMatch {
					mockSubHandler.On("ServeDNS", mock.Anything, mock.Anything).Once()
				}
			} else {
				mockHandler := &nbdns.MockHandler{}
				handler = mockHandler
				if tt.shouldMatch {
					mockHandler.On("ServeDNS", mock.Anything, mock.Anything).Once()
				}
			}

			pattern := tt.handlerDomain
			if tt.isWildcard {
				pattern = "*." + tt.handlerDomain[2:]
			}

			chain.AddHandler(pattern, handler, nbdns.PriorityDefault, nil)

			r := new(dns.Msg)
			r.SetQuestion(tt.queryDomain, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}

			chain.ServeDNS(w, r)

			if h, ok := handler.(*nbdns.MockHandler); ok {
				h.AssertExpectations(t)
			} else if h, ok := handler.(*nbdns.MockSubdomainHandler); ok {
				h.AssertExpectations(t)
			}
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
			var handlers []*nbdns.MockHandler

			// Setup handlers and expectations
			for i := range tt.handlers {
				handler := &nbdns.MockHandler{}
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
	handler1 := &nbdns.MockHandler{}
	handler2 := &nbdns.MockHandler{}
	handler3 := &nbdns.MockHandler{}

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

func TestHandlerChain_PriorityDeregistration(t *testing.T) {
	tests := []struct {
		name string
		ops  []struct {
			action   string // "add" or "remove"
			pattern  string
			priority int
		}
		query         string
		expectedCalls map[int]bool // map[priority]shouldBeCalled
	}{
		{
			name: "remove high priority keeps lower priority handler",
			ops: []struct {
				action   string
				pattern  string
				priority int
			}{
				{"add", "example.com.", nbdns.PriorityDNSRoute},
				{"add", "example.com.", nbdns.PriorityMatchDomain},
				{"remove", "example.com.", nbdns.PriorityDNSRoute},
			},
			query: "example.com.",
			expectedCalls: map[int]bool{
				nbdns.PriorityDNSRoute:    false,
				nbdns.PriorityMatchDomain: true,
			},
		},
		{
			name: "remove lower priority keeps high priority handler",
			ops: []struct {
				action   string
				pattern  string
				priority int
			}{
				{"add", "example.com.", nbdns.PriorityDNSRoute},
				{"add", "example.com.", nbdns.PriorityMatchDomain},
				{"remove", "example.com.", nbdns.PriorityMatchDomain},
			},
			query: "example.com.",
			expectedCalls: map[int]bool{
				nbdns.PriorityDNSRoute:    true,
				nbdns.PriorityMatchDomain: false,
			},
		},
		{
			name: "remove all handlers in order",
			ops: []struct {
				action   string
				pattern  string
				priority int
			}{
				{"add", "example.com.", nbdns.PriorityDNSRoute},
				{"add", "example.com.", nbdns.PriorityMatchDomain},
				{"add", "example.com.", nbdns.PriorityDefault},
				{"remove", "example.com.", nbdns.PriorityDNSRoute},
				{"remove", "example.com.", nbdns.PriorityMatchDomain},
			},
			query: "example.com.",
			expectedCalls: map[int]bool{
				nbdns.PriorityDNSRoute:    false,
				nbdns.PriorityMatchDomain: false,
				nbdns.PriorityDefault:     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := nbdns.NewHandlerChain()
			handlers := make(map[int]*nbdns.MockHandler)

			// Execute operations
			for _, op := range tt.ops {
				if op.action == "add" {
					handler := &nbdns.MockHandler{}
					handlers[op.priority] = handler
					chain.AddHandler(op.pattern, handler, op.priority, nil)
				} else {
					chain.RemoveHandler(op.pattern, op.priority)
				}
			}

			// Create test request
			r := new(dns.Msg)
			r.SetQuestion(tt.query, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}

			// Setup expectations
			for priority, handler := range handlers {
				if shouldCall, exists := tt.expectedCalls[priority]; exists && shouldCall {
					handler.On("ServeDNS", mock.Anything, r).Once()
				} else {
					handler.On("ServeDNS", mock.Anything, r).Maybe()
				}
			}

			// Execute request
			chain.ServeDNS(w, r)

			// Verify expectations
			for _, handler := range handlers {
				handler.AssertExpectations(t)
			}

			// Verify handler exists check
			for priority, shouldExist := range tt.expectedCalls {
				if shouldExist {
					assert.True(t, chain.HasHandlers(tt.ops[0].pattern),
						"Handler chain should have handlers for pattern after removing priority %d", priority)
				}
			}
		})
	}
}

func TestHandlerChain_MultiPriorityHandling(t *testing.T) {
	chain := nbdns.NewHandlerChain()

	testDomain := "example.com."
	testQuery := "test.example.com."

	// Create handlers with MatchSubdomains enabled
	routeHandler := &nbdns.MockSubdomainHandler{Subdomains: true}
	matchHandler := &nbdns.MockSubdomainHandler{Subdomains: true}
	defaultHandler := &nbdns.MockSubdomainHandler{Subdomains: true}

	// Create test request that will be reused
	r := new(dns.Msg)
	r.SetQuestion(testQuery, dns.TypeA)

	// Add handlers in mixed order
	chain.AddHandler(testDomain, defaultHandler, nbdns.PriorityDefault, nil)
	chain.AddHandler(testDomain, routeHandler, nbdns.PriorityDNSRoute, nil)
	chain.AddHandler(testDomain, matchHandler, nbdns.PriorityMatchDomain, nil)

	// Test 1: Initial state with all three handlers
	w := &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}
	// Highest priority handler (routeHandler) should be called
	routeHandler.On("ServeDNS", mock.Anything, r).Return().Once()

	chain.ServeDNS(w, r)
	routeHandler.AssertExpectations(t)

	// Test 2: Remove highest priority handler
	chain.RemoveHandler(testDomain, nbdns.PriorityDNSRoute)
	assert.True(t, chain.HasHandlers(testDomain))

	w = &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}
	// Now middle priority handler (matchHandler) should be called
	matchHandler.On("ServeDNS", mock.Anything, r).Return().Once()

	chain.ServeDNS(w, r)
	matchHandler.AssertExpectations(t)

	// Test 3: Remove middle priority handler
	chain.RemoveHandler(testDomain, nbdns.PriorityMatchDomain)
	assert.True(t, chain.HasHandlers(testDomain))

	w = &nbdns.ResponseWriterChain{ResponseWriter: &mockResponseWriter{}}
	// Now lowest priority handler (defaultHandler) should be called
	defaultHandler.On("ServeDNS", mock.Anything, r).Return().Once()

	chain.ServeDNS(w, r)
	defaultHandler.AssertExpectations(t)

	// Test 4: Remove last handler
	chain.RemoveHandler(testDomain, nbdns.PriorityDefault)
	assert.False(t, chain.HasHandlers(testDomain))
}
