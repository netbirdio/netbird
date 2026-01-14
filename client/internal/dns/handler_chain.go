package dns

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/dns/resutil"
)

const (
	PriorityMgmtCache = 150
	PriorityDNSRoute  = 100
	PriorityLocal     = 75
	PriorityUpstream  = 50
	PriorityDefault   = 1
	PriorityFallback  = -100
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
	requestID      string
	shouldContinue bool
	response       *dns.Msg
	meta           map[string]string
}

// RequestID returns the request ID for tracing
func (w *ResponseWriterChain) RequestID() string {
	return w.requestID
}

// SetMeta sets a metadata key-value pair for logging
func (w *ResponseWriterChain) SetMeta(key, value string) {
	if w.meta == nil {
		w.meta = make(map[string]string)
	}
	w.meta[key] = value
}

func (w *ResponseWriterChain) WriteMsg(m *dns.Msg) error {
	// Check if this is a continue signal (NXDOMAIN with Zero bit set)
	if m.Rcode == dns.RcodeNameError && m.MsgHdr.Zero {
		w.shouldContinue = true
		return nil
	}
	w.response = m
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
func (c *HandlerChain) AddHandler(pattern string, handler dns.Handler, priority int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pattern = strings.ToLower(dns.Fqdn(pattern))
	origPattern := pattern
	isWildcard := strings.HasPrefix(pattern, "*.")
	if isWildcard {
		pattern = pattern[2:]
	}

	// First remove any existing handler with same pattern (case-insensitive) and priority
	c.removeEntry(origPattern, priority)

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
		MatchSubdomains: matchSubdomains,
	}

	pos := c.findHandlerPosition(entry)
	c.handlers = append(c.handlers[:pos], append([]HandlerEntry{entry}, c.handlers[pos:]...)...)

	c.logHandlers()
}

// findHandlerPosition determines where to insert a new handler based on priority and specificity
func (c *HandlerChain) findHandlerPosition(newEntry HandlerEntry) int {
	for i, h := range c.handlers {
		// prio first
		if h.Priority < newEntry.Priority {
			return i
		}

		// domain specificity next
		if h.Priority == newEntry.Priority {
			newDots := strings.Count(newEntry.Pattern, ".")
			existingDots := strings.Count(h.Pattern, ".")
			if newDots > existingDots {
				return i
			}
		}
	}

	// add at end
	return len(c.handlers)
}

// RemoveHandler removes a handler for the given pattern and priority
func (c *HandlerChain) RemoveHandler(pattern string, priority int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pattern = dns.Fqdn(pattern)

	c.removeEntry(pattern, priority)
}

func (c *HandlerChain) removeEntry(pattern string, priority int) {
	// Find and remove handlers matching both original pattern (case-insensitive) and priority
	for i := len(c.handlers) - 1; i >= 0; i-- {
		entry := c.handlers[i]
		if strings.EqualFold(entry.OrigPattern, pattern) && entry.Priority == priority {
			log.Debugf("removing handler pattern: domain=%s priority=%d", entry.OrigPattern, priority)
			c.handlers = append(c.handlers[:i], c.handlers[i+1:]...)
			c.logHandlers()
			break
		}
	}
}

// logHandlers logs the current handler chain state. Caller must hold the lock.
func (c *HandlerChain) logHandlers() {
	if !log.IsLevelEnabled(log.TraceLevel) {
		return
	}

	var b strings.Builder
	b.WriteString("handler chain (" + strconv.Itoa(len(c.handlers)) + "):\n")
	for _, h := range c.handlers {
		b.WriteString("  - pattern: domain=" + h.Pattern + " original: domain=" + h.OrigPattern +
			" wildcard=" + strconv.FormatBool(h.IsWildcard) +
			" match_subdomain=" + strconv.FormatBool(h.MatchSubdomains) +
			" priority=" + strconv.Itoa(h.Priority) + "\n")
	}
	log.Trace(strings.TrimSuffix(b.String(), "\n"))
}

func (c *HandlerChain) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	startTime := time.Now()
	requestID := resutil.GenerateRequestID()
	logger := log.WithFields(log.Fields{
		"request_id": requestID,
		"dns_id":     fmt.Sprintf("%04x", r.Id),
	})

	question := r.Question[0]
	qname := strings.ToLower(question.Name)

	c.mu.RLock()
	handlers := slices.Clone(c.handlers)
	c.mu.RUnlock()

	// Try handlers in priority order
	for _, entry := range handlers {
		if !c.isHandlerMatch(qname, entry) {
			continue
		}

		handlerName := entry.OrigPattern
		if s, ok := entry.Handler.(interface{ String() string }); ok {
			handlerName = s.String()
		}

		logger.Tracef("question: domain=%s type=%s class=%s -> handler=%s pattern=%s wildcard=%v match_subdomain=%v priority=%d",
			qname, dns.TypeToString[question.Qtype], dns.ClassToString[question.Qclass],
			handlerName, entry.OrigPattern, entry.IsWildcard, entry.MatchSubdomains, entry.Priority)

		chainWriter := &ResponseWriterChain{
			ResponseWriter: w,
			origPattern:    entry.OrigPattern,
			requestID:      requestID,
		}
		entry.Handler.ServeDNS(chainWriter, r)

		// If handler wants to continue, try next handler
		if chainWriter.shouldContinue {
			if entry.Priority != PriorityMgmtCache {
				logger.Tracef("handler requested continue for domain=%s", qname)
			}
			continue
		}

		c.logResponse(logger, chainWriter, qname, startTime)
		return
	}

	// No handler matched or all handlers passed
	logger.Tracef("no handler found for domain=%s type=%s class=%s",
		qname, dns.TypeToString[question.Qtype], dns.ClassToString[question.Qclass])
	resp := &dns.Msg{}
	resp.SetRcode(r, dns.RcodeRefused)
	if err := w.WriteMsg(resp); err != nil {
		logger.Errorf("failed to write DNS response: %v", err)
	}
}

func (c *HandlerChain) logResponse(logger *log.Entry, cw *ResponseWriterChain, qname string, startTime time.Time) {
	if cw.response == nil {
		return
	}

	var meta string
	for k, v := range cw.meta {
		meta += " " + k + "=" + v
	}

	logger.Tracef("response: domain=%s rcode=%s answers=%s%s took=%s",
		qname, dns.RcodeToString[cw.response.Rcode], resutil.FormatAnswers(cw.response.Answer),
		meta, time.Since(startTime))
}

func (c *HandlerChain) isHandlerMatch(qname string, entry HandlerEntry) bool {
	switch {
	case entry.Pattern == ".":
		return true
	case entry.IsWildcard:
		parts := strings.Split(strings.TrimSuffix(qname, entry.Pattern), ".")
		return len(parts) >= 2 && strings.HasSuffix(qname, entry.Pattern)
	default:
		// For non-wildcard patterns:
		// If handler wants subdomain matching, allow suffix match
		// Otherwise require exact match
		if entry.MatchSubdomains {
			return strings.EqualFold(qname, entry.Pattern) || strings.HasSuffix(qname, "."+entry.Pattern)
		} else {
			return strings.EqualFold(qname, entry.Pattern)
		}
	}
}
