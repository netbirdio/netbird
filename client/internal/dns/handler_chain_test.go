package dns_test

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/dns/test"
)

// TestHandlerChain_ServeDNS_Priorities tests that handlers are executed in priority order
func TestHandlerChain_ServeDNS_Priorities(t *testing.T) {
	chain := nbdns.NewHandlerChain()

	// Create mock handlers for different priorities
	defaultHandler := &nbdns.MockHandler{}
	matchDomainHandler := &nbdns.MockHandler{}
	dnsRouteHandler := &nbdns.MockHandler{}

	// Setup handlers with different priorities
	chain.AddHandler("example.com.", defaultHandler, nbdns.PriorityDefault)
	chain.AddHandler("example.com.", matchDomainHandler, nbdns.PriorityUpstream)
	chain.AddHandler("example.com.", dnsRouteHandler, nbdns.PriorityDNSRoute)

	// Create test request
	r := new(dns.Msg)
	r.SetQuestion("example.com.", dns.TypeA)

	// Create test writer
	w := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}

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
		{
			name:            "single letter TLD exact match",
			handlerDomain:   "example.x.",
			queryDomain:     "example.x.",
			isWildcard:      false,
			matchSubdomains: false,
			shouldMatch:     true,
		},
		{
			name:            "single letter TLD subdomain match",
			handlerDomain:   "example.x.",
			queryDomain:     "sub.example.x.",
			isWildcard:      false,
			matchSubdomains: true,
			shouldMatch:     true,
		},
		{
			name:            "single letter TLD wildcard match",
			handlerDomain:   "*.example.x.",
			queryDomain:     "sub.example.x.",
			isWildcard:      true,
			matchSubdomains: false,
			shouldMatch:     true,
		},
		{
			name:            "two letter domain labels",
			handlerDomain:   "a.b.",
			queryDomain:     "a.b.",
			isWildcard:      false,
			matchSubdomains: false,
			shouldMatch:     true,
		},
		{
			name:            "single character domain",
			handlerDomain:   "x.",
			queryDomain:     "x.",
			isWildcard:      false,
			matchSubdomains: false,
			shouldMatch:     true,
		},
		{
			name:            "single character domain with subdomain match",
			handlerDomain:   "x.",
			queryDomain:     "sub.x.",
			isWildcard:      false,
			matchSubdomains: true,
			shouldMatch:     true,
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

			chain.AddHandler(pattern, handler, nbdns.PriorityDefault)

			r := new(dns.Msg)
			r.SetQuestion(tt.queryDomain, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}

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
				{pattern: "*.example.com.", priority: nbdns.PriorityUpstream},
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
				{pattern: "test.example.com.", priority: nbdns.PriorityUpstream},
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

				chain.AddHandler(tt.handlers[i].pattern, handler, tt.handlers[i].priority)
			}

			// Create and execute request
			r := new(dns.Msg)
			r.SetQuestion(tt.queryDomain, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}
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
	chain.AddHandler("example.com.", handler1, nbdns.PriorityDNSRoute)
	chain.AddHandler("example.com.", handler2, nbdns.PriorityUpstream)
	chain.AddHandler("example.com.", handler3, nbdns.PriorityDefault)

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
	w := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}
	chain.ServeDNS(w, r)

	// Verify all handlers were called in order
	handler1.AssertExpectations(t)
	handler2.AssertExpectations(t)
	handler3.AssertExpectations(t)
}

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
				{"add", "example.com.", nbdns.PriorityUpstream},
				{"remove", "example.com.", nbdns.PriorityDNSRoute},
			},
			query: "example.com.",
			expectedCalls: map[int]bool{
				nbdns.PriorityDNSRoute: false,
				nbdns.PriorityUpstream: true,
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
				{"add", "example.com.", nbdns.PriorityUpstream},
				{"remove", "example.com.", nbdns.PriorityUpstream},
			},
			query: "example.com.",
			expectedCalls: map[int]bool{
				nbdns.PriorityDNSRoute: true,
				nbdns.PriorityUpstream: false,
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
				{"add", "example.com.", nbdns.PriorityUpstream},
				{"add", "example.com.", nbdns.PriorityDefault},
				{"remove", "example.com.", nbdns.PriorityDNSRoute},
				{"remove", "example.com.", nbdns.PriorityUpstream},
			},
			query: "example.com.",
			expectedCalls: map[int]bool{
				nbdns.PriorityDNSRoute: false,
				nbdns.PriorityUpstream: false,
				nbdns.PriorityDefault:  true,
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
					chain.AddHandler(op.pattern, handler, op.priority)
				} else {
					chain.RemoveHandler(op.pattern, op.priority)
				}
			}

			// Create test request
			r := new(dns.Msg)
			r.SetQuestion(tt.query, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}

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

	// Keep track of mocks for the final assertion in Step 4
	mocks := []*nbdns.MockSubdomainHandler{routeHandler, matchHandler, defaultHandler}

	// Add handlers in mixed order
	chain.AddHandler(testDomain, defaultHandler, nbdns.PriorityDefault)
	chain.AddHandler(testDomain, routeHandler, nbdns.PriorityDNSRoute)
	chain.AddHandler(testDomain, matchHandler, nbdns.PriorityUpstream)

	// Test 1: Initial state
	w1 := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}
	// Highest priority handler (routeHandler) should be called
	routeHandler.On("ServeDNS", mock.Anything, r).Return().Once()
	matchHandler.On("ServeDNS", mock.Anything, r).Maybe()   // Ensure others are not expected yet
	defaultHandler.On("ServeDNS", mock.Anything, r).Maybe() // Ensure others are not expected yet

	chain.ServeDNS(w1, r)
	routeHandler.AssertExpectations(t)

	routeHandler.ExpectedCalls = nil
	routeHandler.Calls = nil
	matchHandler.ExpectedCalls = nil
	matchHandler.Calls = nil
	defaultHandler.ExpectedCalls = nil
	defaultHandler.Calls = nil

	// Test 2: Remove highest priority handler
	chain.RemoveHandler(testDomain, nbdns.PriorityDNSRoute)

	w2 := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}
	// Now middle priority handler (matchHandler) should be called
	matchHandler.On("ServeDNS", mock.Anything, r).Return().Once()
	defaultHandler.On("ServeDNS", mock.Anything, r).Maybe() // Ensure default is not expected yet

	chain.ServeDNS(w2, r)
	matchHandler.AssertExpectations(t)

	matchHandler.ExpectedCalls = nil
	matchHandler.Calls = nil
	defaultHandler.ExpectedCalls = nil
	defaultHandler.Calls = nil

	// Test 3: Remove middle priority handler
	chain.RemoveHandler(testDomain, nbdns.PriorityUpstream)

	w3 := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}
	// Now lowest priority handler (defaultHandler) should be called
	defaultHandler.On("ServeDNS", mock.Anything, r).Return().Once()

	chain.ServeDNS(w3, r)
	defaultHandler.AssertExpectations(t)

	defaultHandler.ExpectedCalls = nil
	defaultHandler.Calls = nil

	// Test 4: Remove last handler
	chain.RemoveHandler(testDomain, nbdns.PriorityDefault)

	w4 := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}
	chain.ServeDNS(w4, r) // Call ServeDNS on the now empty chain for this domain

	for _, m := range mocks {
		m.AssertNumberOfCalls(t, "ServeDNS", 0)
	}
}

func TestHandlerChain_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name        string
		scenario    string
		addHandlers []struct {
			pattern     string
			priority    int
			subdomains  bool
			shouldMatch bool
		}
		query         string
		expectedCalls int
	}{
		{
			name:     "case insensitive exact match",
			scenario: "handler registered lowercase, query uppercase",
			addHandlers: []struct {
				pattern     string
				priority    int
				subdomains  bool
				shouldMatch bool
			}{
				{"example.com.", nbdns.PriorityDefault, false, true},
			},
			query:         "EXAMPLE.COM.",
			expectedCalls: 1,
		},
		{
			name:     "case insensitive wildcard match",
			scenario: "handler registered mixed case wildcard, query different case",
			addHandlers: []struct {
				pattern     string
				priority    int
				subdomains  bool
				shouldMatch bool
			}{
				{"*.Example.Com.", nbdns.PriorityDefault, false, true},
			},
			query:         "sub.EXAMPLE.COM.",
			expectedCalls: 1,
		},
		{
			name:     "multiple handlers different case same domain",
			scenario: "second handler should replace first despite case difference",
			addHandlers: []struct {
				pattern     string
				priority    int
				subdomains  bool
				shouldMatch bool
			}{
				{"EXAMPLE.COM.", nbdns.PriorityDefault, false, false},
				{"example.com.", nbdns.PriorityDefault, false, true},
			},
			query:         "ExAmPlE.cOm.",
			expectedCalls: 1,
		},
		{
			name:     "subdomain matching case insensitive",
			scenario: "handler with MatchSubdomains true should match regardless of case",
			addHandlers: []struct {
				pattern     string
				priority    int
				subdomains  bool
				shouldMatch bool
			}{
				{"example.com.", nbdns.PriorityDefault, true, true},
			},
			query:         "SUB.EXAMPLE.COM.",
			expectedCalls: 1,
		},
		{
			name:     "root zone case insensitive",
			scenario: "root zone handler should match regardless of case",
			addHandlers: []struct {
				pattern     string
				priority    int
				subdomains  bool
				shouldMatch bool
			}{
				{".", nbdns.PriorityDefault, false, true},
			},
			query:         "EXAMPLE.COM.",
			expectedCalls: 1,
		},
		{
			name:     "multiple handlers different priority",
			scenario: "should call higher priority handler despite case differences",
			addHandlers: []struct {
				pattern     string
				priority    int
				subdomains  bool
				shouldMatch bool
			}{
				{"EXAMPLE.COM.", nbdns.PriorityDefault, false, false},
				{"example.com.", nbdns.PriorityUpstream, false, false},
				{"Example.Com.", nbdns.PriorityDNSRoute, false, true},
			},
			query:         "example.com.",
			expectedCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := nbdns.NewHandlerChain()
			handlerCalls := make(map[string]bool) // track which patterns were called

			// Add handlers according to test case
			for _, h := range tt.addHandlers {
				var handler dns.Handler
				pattern := h.pattern // capture pattern for closure

				if h.subdomains {
					subHandler := &nbdns.MockSubdomainHandler{
						Subdomains: true,
					}
					if h.shouldMatch {
						subHandler.On("ServeDNS", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
							handlerCalls[pattern] = true
							w := args.Get(0).(dns.ResponseWriter)
							r := args.Get(1).(*dns.Msg)
							resp := new(dns.Msg)
							resp.SetRcode(r, dns.RcodeSuccess)
							assert.NoError(t, w.WriteMsg(resp))
						}).Once()
					}
					handler = subHandler
				} else {
					mockHandler := &nbdns.MockHandler{}
					if h.shouldMatch {
						mockHandler.On("ServeDNS", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
							handlerCalls[pattern] = true
							w := args.Get(0).(dns.ResponseWriter)
							r := args.Get(1).(*dns.Msg)
							resp := new(dns.Msg)
							resp.SetRcode(r, dns.RcodeSuccess)
							assert.NoError(t, w.WriteMsg(resp))
						}).Once()
					}
					handler = mockHandler
				}

				chain.AddHandler(pattern, handler, h.priority)
			}

			// Execute request
			r := new(dns.Msg)
			r.SetQuestion(tt.query, dns.TypeA)
			chain.ServeDNS(&test.MockResponseWriter{}, r)

			// Verify each handler was called exactly as expected
			for _, h := range tt.addHandlers {
				wasCalled := handlerCalls[h.pattern]
				assert.Equal(t, h.shouldMatch, wasCalled,
					"Handler for pattern %q was %s when it should%s have been",
					h.pattern,
					map[bool]string{true: "called", false: "not called"}[wasCalled],
					map[bool]string{true: "", false: " not"}[wasCalled == h.shouldMatch])
			}

			// Verify total number of calls
			assert.Equal(t, tt.expectedCalls, len(handlerCalls),
				"Wrong number of total handler calls")
		})
	}
}

func TestHandlerChain_DomainSpecificityOrdering(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		ops      []struct {
			action    string
			pattern   string
			priority  int
			subdomain bool
		}
		query         string
		expectedMatch string
	}{
		{
			name:     "more specific domain matches first",
			scenario: "sub.example.com should match before example.com",
			ops: []struct {
				action    string
				pattern   string
				priority  int
				subdomain bool
			}{
				{"add", "example.com.", nbdns.PriorityUpstream, true},
				{"add", "sub.example.com.", nbdns.PriorityUpstream, false},
			},
			query:         "sub.example.com.",
			expectedMatch: "sub.example.com.",
		},
		{
			name:     "more specific domain matches first, both match subdomains",
			scenario: "sub.example.com should match before example.com",
			ops: []struct {
				action    string
				pattern   string
				priority  int
				subdomain bool
			}{
				{"add", "example.com.", nbdns.PriorityUpstream, true},
				{"add", "sub.example.com.", nbdns.PriorityUpstream, true},
			},
			query:         "sub.example.com.",
			expectedMatch: "sub.example.com.",
		},
		{
			name:     "maintain specificity order after removal",
			scenario: "after removing most specific, should fall back to less specific",
			ops: []struct {
				action    string
				pattern   string
				priority  int
				subdomain bool
			}{
				{"add", "example.com.", nbdns.PriorityUpstream, true},
				{"add", "sub.example.com.", nbdns.PriorityUpstream, true},
				{"add", "test.sub.example.com.", nbdns.PriorityUpstream, false},
				{"remove", "test.sub.example.com.", nbdns.PriorityUpstream, false},
			},
			query:         "test.sub.example.com.",
			expectedMatch: "sub.example.com.",
		},
		{
			name:     "priority overrides specificity",
			scenario: "less specific domain with higher priority should match first",
			ops: []struct {
				action    string
				pattern   string
				priority  int
				subdomain bool
			}{
				{"add", "sub.example.com.", nbdns.PriorityUpstream, false},
				{"add", "example.com.", nbdns.PriorityDNSRoute, true},
			},
			query:         "sub.example.com.",
			expectedMatch: "example.com.",
		},
		{
			name:     "equal priority respects specificity",
			scenario: "with equal priority, more specific domain should match",
			ops: []struct {
				action    string
				pattern   string
				priority  int
				subdomain bool
			}{
				{"add", "example.com.", nbdns.PriorityUpstream, true},
				{"add", "other.example.com.", nbdns.PriorityUpstream, true},
				{"add", "sub.example.com.", nbdns.PriorityUpstream, false},
			},
			query:         "sub.example.com.",
			expectedMatch: "sub.example.com.",
		},
		{
			name:     "specific matches before wildcard",
			scenario: "specific domain should match before wildcard at same priority",
			ops: []struct {
				action    string
				pattern   string
				priority  int
				subdomain bool
			}{
				{"add", "*.example.com.", nbdns.PriorityDNSRoute, false},
				{"add", "sub.example.com.", nbdns.PriorityDNSRoute, false},
			},
			query:         "sub.example.com.",
			expectedMatch: "sub.example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := nbdns.NewHandlerChain()
			handlers := make(map[string]*nbdns.MockSubdomainHandler)

			for _, op := range tt.ops {
				if op.action == "add" {
					handler := &nbdns.MockSubdomainHandler{Subdomains: op.subdomain}
					handlers[op.pattern] = handler
					chain.AddHandler(op.pattern, handler, op.priority)
				} else {
					chain.RemoveHandler(op.pattern, op.priority)
				}
			}

			r := new(dns.Msg)
			r.SetQuestion(tt.query, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}

			// Setup handler expectations
			for pattern, handler := range handlers {
				if pattern == tt.expectedMatch {
					handler.On("ServeDNS", mock.Anything, r).Run(func(args mock.Arguments) {
						w := args.Get(0).(dns.ResponseWriter)
						r := args.Get(1).(*dns.Msg)
						resp := new(dns.Msg)
						resp.SetReply(r)
						assert.NoError(t, w.WriteMsg(resp))
					}).Once()
				}
			}

			chain.ServeDNS(w, r)

			for pattern, handler := range handlers {
				if pattern == tt.expectedMatch {
					handler.AssertNumberOfCalls(t, "ServeDNS", 1)
				} else {
					handler.AssertNumberOfCalls(t, "ServeDNS", 0)
				}
			}
		})
	}
}

func TestHandlerChain_AddRemoveRoundtrip(t *testing.T) {
	tests := []struct {
		name            string
		addPattern      string
		removePattern   string
		queryPattern    string
		shouldBeRemoved bool
		description     string
	}{
		{
			name:            "exact same pattern",
			addPattern:      "example.com.",
			removePattern:   "example.com.",
			queryPattern:    "example.com.",
			shouldBeRemoved: true,
			description:     "Adding and removing with identical patterns",
		},
		{
			name:            "case difference",
			addPattern:      "Example.Com.",
			removePattern:   "EXAMPLE.COM.",
			queryPattern:    "example.com.",
			shouldBeRemoved: true,
			description:     "Adding with mixed case, removing with uppercase",
		},
		{
			name:            "reversed case difference",
			addPattern:      "EXAMPLE.ORG.",
			removePattern:   "example.org.",
			queryPattern:    "example.org.",
			shouldBeRemoved: true,
			description:     "Adding with uppercase, removing with lowercase",
		},
		{
			name:            "add wildcard, remove wildcard",
			addPattern:      "*.example.com.",
			removePattern:   "*.example.com.",
			queryPattern:    "sub.example.com.",
			shouldBeRemoved: true,
			description:     "Adding and removing with identical wildcard patterns",
		},
		{
			name:            "add wildcard, remove transformed pattern",
			addPattern:      "*.example.net.",
			removePattern:   "example.net.",
			queryPattern:    "sub.example.net.",
			shouldBeRemoved: false,
			description:     "Adding with wildcard, removing with non-wildcard pattern",
		},
		{
			name:            "add transformed pattern, remove wildcard",
			addPattern:      "example.io.",
			removePattern:   "*.example.io.",
			queryPattern:    "example.io.",
			shouldBeRemoved: false,
			description:     "Adding with non-wildcard pattern, removing with wildcard pattern",
		},
		{
			name:            "trailing dot difference",
			addPattern:      "example.dev",
			removePattern:   "example.dev.",
			queryPattern:    "example.dev.",
			shouldBeRemoved: true,
			description:     "Adding without trailing dot, removing with trailing dot",
		},
		{
			name:            "reversed trailing dot difference",
			addPattern:      "example.app.",
			removePattern:   "example.app",
			queryPattern:    "example.app.",
			shouldBeRemoved: true,
			description:     "Adding with trailing dot, removing without trailing dot",
		},
		{
			name:            "mixed case and wildcard",
			addPattern:      "*.Example.Site.",
			removePattern:   "*.EXAMPLE.SITE.",
			queryPattern:    "sub.example.site.",
			shouldBeRemoved: true,
			description:     "Adding mixed case wildcard, removing uppercase wildcard",
		},
		{
			name:            "root zone",
			addPattern:      ".",
			removePattern:   ".",
			queryPattern:    "random.domain.",
			shouldBeRemoved: true,
			description:     "Adding and removing root zone",
		},
		{
			name:            "wrong domain",
			addPattern:      "example.com.",
			removePattern:   "different.com.",
			queryPattern:    "example.com.",
			shouldBeRemoved: false,
			description:     "Adding one domain, trying to remove a different domain",
		},
		{
			name:            "subdomain mismatch",
			addPattern:      "sub.example.com.",
			removePattern:   "example.com.",
			queryPattern:    "sub.example.com.",
			shouldBeRemoved: false,
			description:     "Adding subdomain, trying to remove parent domain",
		},
		{
			name:            "parent domain mismatch",
			addPattern:      "example.com.",
			removePattern:   "sub.example.com.",
			queryPattern:    "example.com.",
			shouldBeRemoved: false,
			description:     "Adding parent domain, trying to remove subdomain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := nbdns.NewHandlerChain()

			handler := &nbdns.MockHandler{}
			r := new(dns.Msg)
			r.SetQuestion(tt.queryPattern, dns.TypeA)
			w := &nbdns.ResponseWriterChain{ResponseWriter: &test.MockResponseWriter{}}

			// First verify no handler is called before adding any
			chain.ServeDNS(w, r)
			handler.AssertNotCalled(t, "ServeDNS")

			// Add handler
			chain.AddHandler(tt.addPattern, handler, nbdns.PriorityDefault)

			// Verify handler is called after adding
			handler.On("ServeDNS", mock.Anything, r).Once()
			chain.ServeDNS(w, r)
			handler.AssertExpectations(t)

			// Reset mock for the next test
			handler.ExpectedCalls = nil

			// Remove handler
			chain.RemoveHandler(tt.removePattern, nbdns.PriorityDefault)

			// Set up expectations based on whether removal should succeed
			if !tt.shouldBeRemoved {
				handler.On("ServeDNS", mock.Anything, r).Once()
			}

			// Test if handler is still called after removal attempt
			chain.ServeDNS(w, r)

			if tt.shouldBeRemoved {
				handler.AssertNotCalled(t, "ServeDNS",
					"Handler should not be called after successful removal with pattern %q",
					tt.removePattern)
			} else {
				handler.AssertExpectations(t)
				handler.ExpectedCalls = nil
			}
		})
	}
}
