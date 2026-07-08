package middleware

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
)

// chainCloseTimeout bounds how long closeChainsAsync waits for an
// individual chain to drain before forcing teardown. Set to 2x
// MaxTimeout so a middleware blocked on the dispatcher's per-Invoke
// deadline always wins; anything running longer is a runaway and gets
// force-closed.
const chainCloseTimeout = 2 * MaxTimeout

// PathTargetBinding is the minimal per-path binding the server passes
// to Rebuild. It carries the stable keys Manager uses for snapshot
// lookups plus the validated middleware spec list for that path.
type PathTargetBinding struct {
	ServiceID string
	PathID    string
	Specs     []Spec
}

// LiveServiceCheck reports whether the given service ID is still
// present in the proxy's live mapping cache. The Manager calls it
// during InvalidateMiddleware so a chain whose service has been
// removed since the last Rebuild is not resurrected from the binding
// cache, closing the auth-revocation race.
type LiveServiceCheck func(serviceID string) bool

// chainTable holds the immutable per-target chain snapshot. It is
// cloned into a new instance on every Rebuild and swapped in via
// atomic.Pointer. The reverse index byMiddleware lets
// InvalidateMiddleware find the chain keys that reference a given
// middleware without scanning the whole table.
type chainTable struct {
	byTarget     map[string]*Chain
	byMiddleware map[string]map[string]struct{}
}

func newChainTable() *chainTable {
	return &chainTable{
		byTarget:     make(map[string]*Chain),
		byMiddleware: make(map[string]map[string]struct{}),
	}
}

func (c *chainTable) clone() *chainTable {
	out := newChainTable()
	for k, v := range c.byTarget {
		out.byTarget[k] = v
	}
	for id, keys := range c.byMiddleware {
		set := make(map[string]struct{}, len(keys))
		for k := range keys {
			set[k] = struct{}{}
		}
		out.byMiddleware[id] = set
	}
	return out
}

func (c *chainTable) addChain(key string, ch *Chain) {
	c.byTarget[key] = ch
	if ch == nil {
		return
	}
	for _, bm := range ch.all {
		set, ok := c.byMiddleware[bm.spec.ID]
		if !ok {
			set = make(map[string]struct{})
			c.byMiddleware[bm.spec.ID] = set
		}
		set[key] = struct{}{}
	}
}

func (c *chainTable) removeChain(key string) (*Chain, []string) {
	ch, ok := c.byTarget[key]
	if !ok {
		return nil, nil
	}
	delete(c.byTarget, key)
	if ch == nil {
		return nil, nil
	}
	ids := make([]string, 0, len(ch.all))
	for _, bm := range ch.all {
		ids = append(ids, bm.spec.ID)
		set, ok := c.byMiddleware[bm.spec.ID]
		if !ok {
			continue
		}
		delete(set, key)
		if len(set) == 0 {
			delete(c.byMiddleware, bm.spec.ID)
		}
	}
	return ch, ids
}

// Manager owns the per-target middleware chains, the global capture
// budget, and the shared dispatcher. Readers (ChainFor) are lock-free;
// writers (Rebuild, Invalidate*) serialise on writeMu so two
// concurrent mapping updates do not lose writes.
type Manager struct {
	writeMu          sync.Mutex
	chains           atomic.Pointer[chainTable]
	budget           bodytap.Budget
	metrics          *Metrics
	logger           *log.Logger
	dispatcher       *Dispatcher
	resolver         *Resolver
	lastBindings     map[string]PathTargetBinding
	liveServiceCheck atomic.Pointer[LiveServiceCheck]
}

// NewManager constructs a Manager with the given capture budget size.
// A zero or negative budget falls back to bodytap.DefaultCaptureBudgetBytes.
func NewManager(budgetBytes int64, metrics *Metrics, logger *log.Logger) *Manager {
	if metrics == nil {
		metrics, _ = NewMetrics(nil)
	}
	if logger == nil {
		logger = log.StandardLogger()
	}
	if budgetBytes <= 0 {
		budgetBytes = bodytap.DefaultCaptureBudgetBytes
	}
	m := &Manager{
		budget:       bodytap.NewBudget(budgetBytes),
		metrics:      metrics,
		logger:       logger,
		dispatcher:   NewDispatcher(metrics, logger),
		lastBindings: make(map[string]PathTargetBinding),
	}
	m.chains.Store(newChainTable())
	return m
}

// SetResolver installs the resolver used by Rebuild. Safe to call
// once at boot before any Rebuild; not safe to swap concurrently.
func (m *Manager) SetResolver(r *Resolver) {
	m.resolver = r
}

// SetLiveServiceCheck installs a callback the Manager uses to confirm
// a service ID still maps to a live mapping before resurrecting its
// chain from the binding cache during InvalidateMiddleware. A nil fn
// disables the check.
func (m *Manager) SetLiveServiceCheck(fn LiveServiceCheck) {
	if fn == nil {
		m.liveServiceCheck.Store(nil)
		return
	}
	m.liveServiceCheck.Store(&fn)
}

// Budget returns the shared capture budget.
func (m *Manager) Budget() bodytap.Budget {
	return m.budget
}

// Metrics returns the shared metrics bundle.
func (m *Manager) Metrics() *Metrics {
	return m.metrics
}

// Dispatcher returns the shared dispatcher (primarily for testing).
func (m *Manager) Dispatcher() *Dispatcher {
	return m.dispatcher
}

// Rebuild replaces every chain keyed by serviceID with the provided
// bindings. Entries for other services are preserved. Replaced chains
// are closed asynchronously after the atomic swap so in-flight
// requests against the previous chain finish before middleware
// resources are released.
func (m *Manager) Rebuild(serviceID string, bindings []PathTargetBinding) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	cur := m.chains.Load()
	next := cur.clone()

	prefix := serviceID + "|"
	var retired []*Chain
	for k := range cur.byTarget {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		ch, _ := next.removeChain(k)
		if ch != nil {
			retired = append(retired, ch)
		}
		delete(m.lastBindings, k)
	}

	for _, b := range bindings {
		if b.ServiceID != serviceID {
			return fmt.Errorf("binding service %q does not match rebuild service %q", b.ServiceID, serviceID)
		}
		key := chainKey(b.ServiceID, b.PathID)
		m.lastBindings[key] = cloneBinding(b)
		chain := m.buildChain(b)
		if chain == nil || chain.Empty() {
			delete(m.lastBindings, key)
			continue
		}
		next.addChain(key, chain)
	}

	m.chains.Store(next)
	m.closeChainsAsync(retired)
	return nil
}

// Invalidate drops every chain for the given service ID.
func (m *Manager) Invalidate(serviceID string) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	cur := m.chains.Load()
	next := cur.clone()
	prefix := serviceID + "|"
	var retired []*Chain
	for k := range cur.byTarget {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		ch, _ := next.removeChain(k)
		if ch != nil {
			retired = append(retired, ch)
		}
		delete(m.lastBindings, k)
	}
	for k := range m.lastBindings {
		if strings.HasPrefix(k, prefix) {
			delete(m.lastBindings, k)
		}
	}
	m.chains.Store(next)
	m.closeChainsAsync(retired)
}

// InvalidateMiddleware rebuilds only the chains that reference id.
func (m *Manager) InvalidateMiddleware(id string) {
	if id == "" {
		return
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	cur := m.chains.Load()
	keys, ok := cur.byMiddleware[id]
	if !ok || len(keys) == 0 {
		return
	}

	affected := make([]string, 0, len(keys))
	for k := range keys {
		affected = append(affected, k)
	}

	next := cur.clone()
	var retired []*Chain
	check := m.loadLiveServiceCheck()
	for _, k := range affected {
		ch, _ := next.removeChain(k)
		if ch != nil {
			retired = append(retired, ch)
		}
		b, ok := m.lastBindings[k]
		if !ok {
			delete(m.lastBindings, k)
			continue
		}
		if check != nil && !check(b.ServiceID) {
			m.logger.Debugf("middleware %s: skipping rebuild for %s; service no longer live", id, k)
			delete(m.lastBindings, k)
			continue
		}
		chain := m.buildChain(b)
		if chain == nil || chain.Empty() {
			delete(m.lastBindings, k)
			continue
		}
		next.addChain(k, chain)
	}

	m.chains.Store(next)
	m.closeChainsAsync(retired)
}

func (m *Manager) loadLiveServiceCheck() LiveServiceCheck {
	p := m.liveServiceCheck.Load()
	if p == nil {
		return nil
	}
	return *p
}

// InvalidateAll drops every chain.
func (m *Manager) InvalidateAll() {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	cur := m.chains.Load()
	retired := make([]*Chain, 0, len(cur.byTarget))
	for _, c := range cur.byTarget {
		retired = append(retired, c)
	}
	m.chains.Store(newChainTable())
	for k := range m.lastBindings {
		delete(m.lastBindings, k)
	}
	m.closeChainsAsync(retired)
}

func (m *Manager) closeChainsAsync(retired []*Chain) {
	if len(retired) == 0 {
		return
	}
	chains := make([]*Chain, len(retired))
	copy(chains, retired)
	go func() {
		for _, c := range chains {
			ctx, cancel := context.WithTimeout(context.Background(), chainCloseTimeout)
			start := time.Now()
			if err := c.Close(ctx); err != nil {
				if m.metrics != nil {
					m.metrics.IncError(context.Background(), c.TargetID(), "chain_close_timeout")
				}
				m.logger.Warnf("middleware chain %s close exceeded %s after %s: %v",
					c.TargetID(), chainCloseTimeout, time.Since(start), err)
			}
			cancel()
		}
	}()
}

// ChainFor returns the chain for serviceID/pathID or nil if none is
// registered. Lock-free.
func (m *Manager) ChainFor(serviceID, pathID string) *Chain {
	tbl := m.chains.Load()
	if tbl == nil {
		return nil
	}
	c, ok := tbl.byTarget[chainKey(serviceID, pathID)]
	if !ok {
		return nil
	}
	return c
}

// buildChain resolves each enabled spec and returns the assembled
// chain. Returns a nil chain when no middlewares are bound; resolver
// errors per middleware are logged and counted but do not abort the
// chain.
func (m *Manager) buildChain(b PathTargetBinding) *Chain {
	if len(b.Specs) == 0 || m.resolver == nil {
		return nil
	}

	bound := make([]boundMiddleware, 0, len(b.Specs))
	for _, spec := range b.Specs {
		if !spec.Enabled {
			continue
		}
		mw, merged, err := m.resolver.Resolve(spec)
		if err != nil {
			m.logger.Warnf("middleware %s resolve on target %s/%s: %v", spec.ID, b.ServiceID, b.PathID, err)
			m.metrics.IncError(context.Background(), spec.ID, "resolve_error")
			continue
		}
		if mw == nil {
			continue
		}
		bound = append(bound, boundMiddleware{spec: merged, mw: mw})
	}
	if len(bound) == 0 {
		return nil
	}
	return NewChain(chainKey(b.ServiceID, b.PathID), bound, m.dispatcher)
}

// cloneBinding returns a deep copy of b suitable for caching across
// mapping updates.
func cloneBinding(b PathTargetBinding) PathTargetBinding {
	out := PathTargetBinding{
		ServiceID: b.ServiceID,
		PathID:    b.PathID,
	}
	if len(b.Specs) == 0 {
		return out
	}
	out.Specs = make([]Spec, len(b.Specs))
	for i, s := range b.Specs {
		out.Specs[i] = s.Clone()
	}
	return out
}

func chainKey(serviceID, pathID string) string {
	return serviceID + "|" + pathID
}
