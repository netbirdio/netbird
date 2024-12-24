package dns

import (
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	PriorityDNSRoute    = 100
	PriorityMatchDomain = 50
	PriorityDefault     = 0
)

type SubdomainMatcher interface {
	dns.Handler
	MatchSubdomains() bool
}

type HandlerEntry struct {
	Handler         dns.Handler
	Priority        int
	Pattern         string
	OrigPattern     string
	IsWildcard      bool
	StopHandler     handlerWithStop
	MatchSubdomains bool
}

// HandlerChain represents a prioritized chain of DNS handlers
type HandlerChain struct {
	mu       sync.RWMutex
	handlers []HandlerEntry
}

// ResponseWriterChain wraps a dns.ResponseWriter to track if handler wants to continue chain
type ResponseWriterChain struct {
	dns.ResponseWriter
	origPattern    string
	shouldContinue bool
}

func (w *ResponseWriterChain) WriteMsg(m *dns.Msg) error {
	// Check if this is a continue signal (NXDOMAIN with Zero bit set)
	if m.Rcode == dns.RcodeNameError && m.MsgHdr.Zero {
		w.shouldContinue = true
		return nil
	}
	return w.ResponseWriter.WriteMsg(m)
}

func NewHandlerChain() *HandlerChain {
	return &HandlerChain{
		handlers: make([]HandlerEntry, 0),
	}
}

// GetOrigPattern returns the original pattern of the handler that wrote the response
func (w *ResponseWriterChain) GetOrigPattern() string {
	return w.origPattern
}

// AddHandler adds a new handler to the chain, replacing any existing handler with the same pattern and priority
func (c *HandlerChain) AddHandler(pattern string, handler dns.Handler, priority int, stopHandler handlerWithStop) {
	c.mu.Lock()
	defer c.mu.Unlock()

	origPattern := pattern
	isWildcard := strings.HasPrefix(pattern, "*.")
	if isWildcard {
		pattern = pattern[2:]
	}
	pattern = dns.Fqdn(pattern)
	origPattern = dns.Fqdn(origPattern)

	// First remove any existing handler with same original pattern and priority
	for i := len(c.handlers) - 1; i >= 0; i-- {
		if c.handlers[i].OrigPattern == origPattern && c.handlers[i].Priority == priority {
			if c.handlers[i].StopHandler != nil {
				c.handlers[i].StopHandler.stop()
			}
			c.handlers = append(c.handlers[:i], c.handlers[i+1:]...)
			break
		}
	}

	// Check if handler implements SubdomainMatcher interface
	matchSubdomains := false
	if matcher, ok := handler.(SubdomainMatcher); ok {
		matchSubdomains = matcher.MatchSubdomains()
	}

	log.Debugf("adding handler pattern: domain=%s original: domain=%s wildcard=%v match_subdomain=%v priority=%d",
		pattern, origPattern, isWildcard, matchSubdomains, priority)

	entry := HandlerEntry{
		Handler:         handler,
		Priority:        priority,
		Pattern:         pattern,
		OrigPattern:     origPattern,
		IsWildcard:      isWildcard,
		StopHandler:     stopHandler,
		MatchSubdomains: matchSubdomains,
	}

	// Insert handler in priority order
	pos := 0
	for i, h := range c.handlers {
		if h.Priority < priority {
			pos = i
			break
		}
		pos = i + 1
	}

	c.handlers = append(c.handlers[:pos], append([]HandlerEntry{entry}, c.handlers[pos:]...)...)
}

// RemoveHandler removes a handler for the given pattern and priority
func (c *HandlerChain) RemoveHandler(pattern string, priority int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pattern = dns.Fqdn(pattern)

	// Find and remove handlers matching both original pattern and priority
	for i := len(c.handlers) - 1; i >= 0; i-- {
		entry := c.handlers[i]
		if entry.OrigPattern == pattern && entry.Priority == priority {
			if entry.StopHandler != nil {
				entry.StopHandler.stop()
			}
			c.handlers = append(c.handlers[:i], c.handlers[i+1:]...)
			return
		}
	}
}

// HasHandlers returns true if there are any handlers remaining for the given pattern
func (c *HandlerChain) HasHandlers(pattern string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pattern = dns.Fqdn(pattern)
	for _, entry := range c.handlers {
		if entry.Pattern == pattern {
			return true
		}
	}
	return false
}

func (c *HandlerChain) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	qname := r.Question[0].Name
	log.Tracef("handling DNS request for domain=%s", qname)

	c.mu.RLock()
	handlers := slices.Clone(c.handlers)
	c.mu.RUnlock()

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("current handlers (%d):", len(handlers))
		for _, h := range handlers {
			log.Tracef("  - pattern: domain=%s original: domain=%s wildcard=%v priority=%d",
				h.Pattern, h.OrigPattern, h.IsWildcard, h.Priority)
		}
	}

	// Try handlers in priority order
	for _, entry := range handlers {
		var matched bool
		switch {
		case entry.Pattern == ".":
			matched = true
		case entry.IsWildcard:
			parts := strings.Split(strings.TrimSuffix(qname, entry.Pattern), ".")
			matched = len(parts) >= 2 && strings.HasSuffix(qname, entry.Pattern)
		default:
			// For non-wildcard patterns:
			// If handler wants subdomain matching, allow suffix match
			// Otherwise require exact match
			if entry.MatchSubdomains {
				matched = qname == entry.Pattern || strings.HasSuffix(qname, "."+entry.Pattern)
			} else {
				matched = qname == entry.Pattern
			}
		}

		if !matched {
			log.Tracef("trying domain match: request: domain=%s pattern: domain=%s wildcard=%v match_subdomain=%v matched=false",
				qname, entry.OrigPattern, entry.MatchSubdomains, entry.IsWildcard)
			continue
		}

		log.Tracef("handler matched: request: domain=%s pattern: domain=%s wildcard=%v match_subdomain=%v",
			qname, entry.OrigPattern, entry.IsWildcard, entry.MatchSubdomains)

		chainWriter := &ResponseWriterChain{
			ResponseWriter: w,
			origPattern:    entry.OrigPattern,
		}
		entry.Handler.ServeDNS(chainWriter, r)

		// If handler wants to continue, try next handler
		if chainWriter.shouldContinue {
			log.Tracef("handler requested continue to next handler")
			continue
		}
		return
	}

	// No handler matched or all handlers passed
	log.Tracef("no handler found for domain=%s", qname)
	resp := &dns.Msg{}
	resp.SetRcode(r, dns.RcodeNameError)
	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write DNS response: %v", err)
	}
}
