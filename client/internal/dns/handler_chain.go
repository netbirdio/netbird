package dns

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net"
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

// responseMeta holds the annotations handlers attach to a request to explain the
// response the chain ends up writing. It survives a deferral, so an answer that
// did not come from the handler that owns the name still says who stepped aside
// and why.
type responseMeta map[resutil.MetaKey]string

// format renders the annotations for the response log line. The order is stable
// so the same event reads the same way every time; a map's own order is not.
func (m responseMeta) format() string {
	if len(m) == 0 {
		return ""
	}

	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		b.WriteString(" " + string(k) + "=" + m[k])
	}
	return b.String()
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
	// softNegative suppresses a poisoning negative verdict for this request. A
	// handler that owns the name but cannot answer this query type sets it
	// before deferring, and it stays set for every handler that runs after.
	softNegative bool
	// clientHasEdns records whether the original query advertised EDNS0, taken
	// before any handler ran: handlers add EDNS0 to the query they forward
	// upstream, so the message itself no longer answers the question later.
	clientHasEdns bool
	response      *dns.Msg
	// meta is handed to the next handler when this one defers, so the same map
	// outlives the writer that created it. Handlers must only set metadata from
	// within ServeDNS, never from a goroutine that outlives the call.
	meta responseMeta
}

// RequestID returns the request ID for tracing
func (w *ResponseWriterChain) RequestID() string {
	return w.requestID
}

// SetMeta sets a metadata key-value pair for logging
func (w *ResponseWriterChain) SetMeta(key resutil.MetaKey, value string) {
	if w.meta == nil {
		w.meta = make(responseMeta)
	}
	w.meta[key] = value
}

// RequestSoftNegative marks the request so a downstream NXDOMAIN is turned into
// NODATA before it reaches the client. Set by a handler that defers a query for
// a name it owns but a type it cannot resolve.
func (w *ResponseWriterChain) RequestSoftNegative() {
	w.softNegative = true
}

func (w *ResponseWriterChain) WriteMsg(m *dns.Msg) error {
	// Check if this is a continue signal (NXDOMAIN with Zero bit set)
	if m.Rcode == dns.RcodeNameError && m.MsgHdr.Zero {
		w.shouldContinue = true
		return nil
	}
	if w.softNegative && m.Rcode == dns.RcodeNameError {
		m = softenNegative(m, w.clientHasEdns)
		w.SetMeta(resutil.MetaKeySoftened, "nxdomain->nodata")
	}
	w.response = m
	if m.MsgHdr.Truncated {
		w.SetMeta(resutil.MetaKeyTruncated, "true")
	}
	return w.ResponseWriter.WriteMsg(m)
}

// softenNegative downgrades an NXDOMAIN to NODATA for a request a handler that
// owns the name deferred. NXDOMAIN is cached for the name and every type below
// it, so a resolver that has never heard of a routed name would take out the
// record types the route does serve; NODATA is cached for this name and type
// only. The authority section goes with it: the negative TTL of a zone we just
// overruled does not apply, and RFC 2308 keeps a negative answer that carries no
// SOA out of caches altogether, so the rewrite cannot outlive the route.
//
// The rewrite is ours, not the answering resolver's, so an EDNS0 client is told
// as much: the reply we hand back travels a path no capture on this host sees,
// and an empty answer is otherwise indistinguishable from a real one. Returns a
// copy so the answering handler keeps whatever it may hold on to.
func softenNegative(m *dns.Msg, clientHasEdns bool) *dns.Msg {
	out := m.Copy()
	out.Rcode = dns.RcodeSuccess
	out.Ns = nil

	if clientHasEdns {
		resutil.AttachEDE(out, resutil.EDENetbirdSoftenedNegative,
			"netbird: name is served locally, NXDOMAIN from the fallthrough resolver suppressed")
	} else {
		resutil.StripOPT(out)
	}

	return out
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
	c.dispatch(w, r, math.MaxInt)
}

// dispatch routes a DNS request through the chain, skipping handlers with
// priority > maxPriority. Shared by ServeDNS and ResolveInternal.
func (c *HandlerChain) dispatch(w dns.ResponseWriter, r *dns.Msg, maxPriority int) {
	if len(r.Question) == 0 {
		return
	}

	startTime := time.Now()
	requestID := resutil.GenerateRequestID()
	fields := log.Fields{
		"request_id": requestID,
		"dns_id":     fmt.Sprintf("%04x", r.Id),
	}
	if addr := w.RemoteAddr(); addr != nil {
		fields["client"] = addr.String()
	}
	logger := log.WithFields(fields)

	question := r.Question[0]
	qname := strings.ToLower(question.Name)

	c.mu.RLock()
	handlers := slices.Clone(c.handlers)
	c.mu.RUnlock()

	// Carried across deferrals: once a handler that owns the name defers, no
	// handler after it may answer with a verdict that poisons the name. The
	// metadata of a handler that stepped aside is carried too, so the response
	// log line explains an answer that did not come from the handler that owns
	// the name.
	var softNegative bool
	var carried responseMeta

	// Taken before any handler runs: handlers advertise EDNS0 on the query they
	// forward upstream, so afterwards the message no longer tells us whether the
	// client did.
	clientHasEdns := r.IsEdns0() != nil

	// Try handlers in priority order
	for _, entry := range handlers {
		if entry.Priority > maxPriority {
			continue
		}
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
			softNegative:   softNegative,
			clientHasEdns:  clientHasEdns,
			meta:           carried,
		}
		entry.Handler.ServeDNS(chainWriter, r)

		// If handler wants to continue, try next handler
		if chainWriter.shouldContinue {
			softNegative = softNegative || chainWriter.softNegative
			carried = chainWriter.meta
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
	// A handler that owns the name deferred and nothing below it could answer
	// (a client with no primary nameserver group). The name exists as far as
	// this client is concerned, since the route serves its addresses, so REFUSED
	// would contradict the route: a stub that takes it as "not served here" and
	// retries another resolver can come back with an NXDOMAIN that takes the
	// whole name down. Answer "no records of this type" instead, without an SOA,
	// so RFC 2308 keeps it out of negative caches, and tell an EDNS0 client the
	// empty answer is ours rather than a resolver's.
	if softNegative {
		resp.Rcode = dns.RcodeSuccess
		if clientHasEdns {
			resutil.AttachEDE(resp, resutil.EDENetbirdSoftenedNegative,
				"netbird: name is served locally, no fallthrough resolver for this query type")
		}
		// logResponse never runs on this path, so the carried metadata is
		// appended here or the reason for the deferral is lost in exactly the
		// case that is hardest to diagnose.
		logger.Tracef("no handler below the deferring one for domain=%s type=%s, answering NODATA%s",
			qname, dns.TypeToString[question.Qtype], carried.format())
	}
	if err := w.WriteMsg(resp); err != nil {
		logger.Errorf("failed to write DNS response: %v", err)
	}
}

func (c *HandlerChain) logResponse(logger *log.Entry, cw *ResponseWriterChain, qname string, startTime time.Time) {
	// Runs for every query, and the arguments below are not free: Len() packs
	// the message to measure it, and formatting the answers and the metadata
	// allocates. None of it is worth doing when the line is discarded.
	if !log.IsLevelEnabled(log.TraceLevel) {
		return
	}

	if cw.response == nil {
		return
	}

	logger.Tracef("response: domain=%s rcode=%s answers=%s size=%dB%s took=%s",
		qname, dns.RcodeToString[cw.response.Rcode], resutil.FormatAnswers(cw.response.Answer),
		cw.response.Len(), cw.meta.format(), time.Since(startTime))
}

// ResolveInternal runs an in-process DNS query against the chain, skipping any
// handler with priority > maxPriority. Used by internal callers (e.g. the mgmt
// cache refresher) that must bypass themselves to avoid loops.
//
// "Nothing answered" is read off RcodeRefused, which a request soft-negatived by
// a deferring handler never carries: it ends in an empty NOERROR instead, and
// would look resolved. No caller can reach that today, since every handler that
// defers sits above the maxPriority any caller passes. Lowering one below it
// means this check needs the soft-negative case too.
//
// Honors ctx cancellation; on ctx.Done the dispatch goroutine is left to drain on its own
// (bounded by the invoked handler's internal timeout).
func (c *HandlerChain) ResolveInternal(ctx context.Context, r *dns.Msg, maxPriority int) (*dns.Msg, error) {
	if len(r.Question) == 0 {
		return nil, fmt.Errorf("empty question")
	}

	base := &internalResponseWriter{}
	done := make(chan struct{})
	go func() {
		c.dispatch(base, r, maxPriority)
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		// Prefer a completed response if dispatch finished concurrently with cancellation.
		select {
		case <-done:
		default:
			return nil, fmt.Errorf("resolve %s: %w", strings.ToLower(r.Question[0].Name), ctx.Err())
		}
	}

	if base.response == nil || base.response.Rcode == dns.RcodeRefused {
		return nil, fmt.Errorf("no handler resolved %s at priority ≤ %d",
			strings.ToLower(r.Question[0].Name), maxPriority)
	}
	return base.response, nil
}

// HasRootHandlerAtOrBelow reports whether any "." handler is registered at
// priority ≤ maxPriority.
func (c *HandlerChain) HasRootHandlerAtOrBelow(maxPriority int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, h := range c.handlers {
		if h.Pattern == "." && h.Priority <= maxPriority {
			return true
		}
	}
	return false
}

func (c *HandlerChain) isHandlerMatch(qname string, entry HandlerEntry) bool {
	switch {
	case entry.Pattern == ".":
		return true
	case entry.IsWildcard:
		return strings.HasSuffix(qname, "."+entry.Pattern)
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

// internalResponseWriter captures a dns.Msg for in-process chain queries.
type internalResponseWriter struct {
	response *dns.Msg
}

func (w *internalResponseWriter) WriteMsg(m *dns.Msg) error { w.response = m; return nil }
func (w *internalResponseWriter) LocalAddr() net.Addr       { return nil }
func (w *internalResponseWriter) RemoteAddr() net.Addr      { return nil }

// Write unpacks raw DNS bytes so handlers that call Write instead of WriteMsg
// still surface their answer to ResolveInternal.
func (w *internalResponseWriter) Write(p []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(p); err != nil {
		return 0, err
	}
	w.response = msg
	return len(p), nil
}

func (w *internalResponseWriter) Close() error      { return nil }
func (w *internalResponseWriter) TsigStatus() error { return nil }

// TsigTimersOnly is part of dns.ResponseWriter.
func (w *internalResponseWriter) TsigTimersOnly(bool) {
	// no-op: in-process queries carry no TSIG state.
}

// Hijack is part of dns.ResponseWriter.
func (w *internalResponseWriter) Hijack() {
	// no-op: in-process queries have no underlying connection to hand off.
}
