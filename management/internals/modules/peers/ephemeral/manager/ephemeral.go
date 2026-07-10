package manager

import (
	"context"
	"math/rand"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	// cleanupWindow is the small grace period added on top of the
	// staleness horizon before a sweep fires. It absorbs minor clock
	// skew between the management server and the database and avoids
	// firing a sweep right at the boundary where last_seen could still
	// be one tick under the threshold.
	cleanupWindow = 1 * time.Minute

	// initialLoadMinDelay and initialLoadMaxDelay bracket the random
	// delay applied before the post-restart catch-up query runs. Spread
	// across replicas this prevents a thundering herd of catch-up
	// queries hitting the database simultaneously after a deploy.
	initialLoadMinDelay = 8 * time.Minute
	initialLoadMaxDelay = 10 * time.Minute
)

var (
	timeNow = time.Now
)

// accountEntry is the per-account state held by the cleanup tracker.
// We don't track which peers are pending — the sweep query gets the
// authoritative list straight from the database every time. We only
// need to know the latest disconnect we've observed for this account
// (so we can decide when it's safe to drop the entry) and the timer
// that will fire the next sweep.
type accountEntry struct {
	lastDisconnectedAt time.Time
	timer              *time.Timer
}

// EphemeralManager tracks accounts that may have ephemeral peers in
// need of cleanup and runs a per-account sweep at the appropriate
// time. State is in-memory and account-scoped: a sweep deletes any
// ephemeral peer in the account that has been disconnected for at
// least lifeTime, then either drops the account from the tracker
// (when no recent disconnects have arrived) or re-arms the timer.
type EphemeralManager struct {
	store        store.Store
	peersManager peers.Manager

	accountsLock sync.Mutex
	accounts     map[string]*accountEntry

	// initialLoadTimer is the one-shot timer used to defer the
	// post-restart catch-up query; held so Stop() can cancel it.
	initialLoadTimer *time.Timer
	// stopped is flipped by Stop() so any timer that fires after
	// teardown becomes a no-op instead of touching a half-dismantled
	// store.
	stopped bool

	lifeTime      time.Duration
	cleanupWindow time.Duration

	// initialLoadDelay returns the wall-clock delay to wait before
	// running the post-restart catch-up query. Pluggable so tests can
	// fire the load immediately.
	initialLoadDelay func() time.Duration

	// bgCtx is the long-lived context captured at LoadInitialPeers
	// time. Timer-driven sweeps use it because they fire long after
	// the original gRPC handler ctx that produced an OnPeerDisconnected
	// call has been cancelled.
	bgCtx context.Context

	// metrics is nil-safe; methods on telemetry.EphemeralPeersMetrics
	// no-op when the receiver is nil so deployments without an app
	// metrics provider work unchanged.
	metrics *telemetry.EphemeralPeersMetrics
}

// NewEphemeralManager instantiate new EphemeralManager
func NewEphemeralManager(store store.Store, peersManager peers.Manager) *EphemeralManager {
	return &EphemeralManager{
		store:            store,
		peersManager:     peersManager,
		accounts:         make(map[string]*accountEntry),
		lifeTime:         ephemeral.EphemeralLifeTime,
		cleanupWindow:    cleanupWindow,
		initialLoadDelay: defaultInitialLoadDelay,
	}
}

// SetMetrics attaches a metrics collector. Pass nil to detach.
func (e *EphemeralManager) SetMetrics(m *telemetry.EphemeralPeersMetrics) {
	e.accountsLock.Lock()
	e.metrics = m
	e.accountsLock.Unlock()
}

// LoadInitialPeers schedules the post-restart catch-up query for a
// random moment 8-10 minutes from now. Returns immediately. The
// catch-up populates the per-account tracker from the database so any
// peers that disconnected before the restart still get cleaned up.
//
// The random delay is critical: without it, every management replica
// hitting the same Postgres instance after a deploy would issue the
// catch-up query simultaneously.
func (e *EphemeralManager) LoadInitialPeers(ctx context.Context) {
	e.accountsLock.Lock()
	defer e.accountsLock.Unlock()
	if e.stopped {
		return
	}

	e.bgCtx = ctx

	delay := e.initialLoadDelay()
	log.WithContext(ctx).Infof("ephemeral peer initial load scheduled in %s", delay)
	e.initialLoadTimer = time.AfterFunc(delay, func() {
		e.loadInitialAccounts(e.bgCtx)
	})
}

// Stop cancels the deferred initial load and any per-account timers.
func (e *EphemeralManager) Stop() {
	e.accountsLock.Lock()
	defer e.accountsLock.Unlock()

	e.stopped = true
	if e.initialLoadTimer != nil {
		e.initialLoadTimer.Stop()
		e.initialLoadTimer = nil
	}
	for _, entry := range e.accounts {
		if entry.timer != nil {
			entry.timer.Stop()
		}
	}
	e.accounts = make(map[string]*accountEntry)
}

// OnPeerConnected is a no-op in the account-scoped design. The sweep
// query filters out connected peers at the database level, so we don't
// need an explicit "remove from list" signal when a peer reconnects.
// Kept on the interface to preserve the existing call sites.
func (e *EphemeralManager) OnPeerConnected(_ context.Context, _ *nbpeer.Peer) {
}

// OnPeerDisconnected registers a disconnect for the peer's account and
// arms a sweep if one isn't already scheduled. Non-ephemeral peers are
// ignored.
func (e *EphemeralManager) OnPeerDisconnected(ctx context.Context, peer *nbpeer.Peer) {
	if !peer.Ephemeral {
		return
	}

	now := timeNow()

	e.accountsLock.Lock()
	defer e.accountsLock.Unlock()
	if e.stopped {
		return
	}

	entry, existed := e.accounts[peer.AccountID]
	if !existed {
		entry = &accountEntry{}
		e.accounts[peer.AccountID] = entry
		e.metrics.IncPending()
	}
	entry.lastDisconnectedAt = now

	if entry.timer == nil {
		delay := e.lifeTime + e.cleanupWindow
		log.WithContext(ctx).Tracef("ephemeral: scheduling sweep for account %s in %s", peer.AccountID, delay)
		accountID := peer.AccountID
		entry.timer = time.AfterFunc(delay, func() {
			e.sweep(e.bgCtxOrFallback(ctx), accountID)
		})
	}
}

// bgCtxOrFallback returns the long-lived background context captured at
// LoadInitialPeers time, falling back to the supplied ctx when the
// manager hasn't been started through LoadInitialPeers (e.g. in tests
// that drive the manager directly). Must be called with the lock held
// or before the timer is armed.
func (e *EphemeralManager) bgCtxOrFallback(ctx context.Context) context.Context {
	if e.bgCtx != nil {
		return e.bgCtx
	}
	return ctx
}

// loadInitialAccounts runs the post-restart catch-up query and seeds
// the tracker with one entry per account that has at least one
// disconnected ephemeral peer.
func (e *EphemeralManager) loadInitialAccounts(ctx context.Context) {
	accounts, err := e.store.GetEphemeralAccountsLastDisconnect(ctx)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to load ephemeral accounts on startup: %v", err)
		return
	}

	now := timeNow()
	added := 0

	e.accountsLock.Lock()
	defer e.accountsLock.Unlock()
	if e.stopped {
		return
	}

	for accountID, lastDisc := range accounts {
		// If we already learned about this account via an
		// OnPeerDisconnected that arrived during the random delay
		// window, prefer the live timestamp.
		if _, alreadyTracked := e.accounts[accountID]; alreadyTracked {
			continue
		}

		entry := &accountEntry{lastDisconnectedAt: lastDisc}
		horizon := lastDisc.Add(e.lifeTime)

		var delay time.Duration
		if horizon.After(now) {
			delay = horizon.Sub(now) + e.cleanupWindow
		} else {
			// Already past the staleness window — sweep right away
			// (one cleanupWindow later, to keep startup load smooth
			// when many accounts qualify at once).
			delay = e.cleanupWindow
		}
		idForClosure := accountID
		entry.timer = time.AfterFunc(delay, func() {
			e.sweep(ctx, idForClosure)
		})
		e.accounts[accountID] = entry
		added++
	}

	e.metrics.AddPending(int64(added))
	log.WithContext(ctx).Debugf("ephemeral: loaded %d account(s) for cleanup tracking", added)
}

// sweep runs the cleanup pass for a single account. It queries the
// database for disconnected ephemeral peers that have crossed the
// staleness window, deletes them via peers.Manager, and then decides
// whether to drop the account from the tracker or re-arm the timer.
func (e *EphemeralManager) sweep(ctx context.Context, accountID string) {
	now := timeNow()

	e.accountsLock.Lock()
	entry, ok := e.accounts[accountID]
	if !ok || e.stopped {
		e.accountsLock.Unlock()
		return
	}
	lastDisc := entry.lastDisconnectedAt
	entry.timer = nil
	e.accountsLock.Unlock()

	threshold := now.Add(-e.lifeTime)
	stalePeerIDs, err := e.store.GetStaleEphemeralPeerIDsForAccount(ctx, accountID, threshold)
	if err != nil {
		log.WithContext(ctx).Errorf("ephemeral: failed to query stale peers for account %s: %v", accountID, err)
		e.metrics.CountCleanupError()
		e.rearm(ctx, accountID, e.cleanupWindow)
		return
	}

	if len(stalePeerIDs) > 0 {
		log.WithContext(ctx).Tracef("ephemeral: deleting %d peer(s) for account %s", len(stalePeerIDs), accountID)
		if err := e.peersManager.DeletePeers(ctx, accountID, stalePeerIDs, activity.SystemInitiator, true); err != nil {
			log.WithContext(ctx).Errorf("ephemeral: failed to delete peers for account %s: %v", accountID, err)
			e.metrics.CountCleanupError()
			e.rearm(ctx, accountID, e.cleanupWindow)
			return
		}
		e.metrics.CountCleanupRun()
		e.metrics.CountPeersCleaned(int64(len(stalePeerIDs)))
	}

	e.accountsLock.Lock()
	defer e.accountsLock.Unlock()
	if e.stopped {
		return
	}
	entry, ok = e.accounts[accountID]
	if !ok {
		return
	}

	// Drop rule: if every disconnect we've observed has now crossed
	// the staleness window, the sweep we just ran saw everything that
	// could possibly need cleaning. Dropping is safe — a future
	// disconnect will recreate the entry. The check uses the latest
	// lastDisc, which may have advanced (concurrently with the sweep
	// itself) due to a new OnPeerDisconnected, in which case we
	// correctly re-arm.
	horizon := entry.lastDisconnectedAt.Add(e.lifeTime)
	if !horizon.After(now) {
		delete(e.accounts, accountID)
		e.metrics.DecPending(1)
		log.WithContext(ctx).Tracef("ephemeral: dropping account %s (lastDisc=%s, horizon=%s, now=%s)",
			accountID, lastDisc, horizon, now)
		return
	}

	delay := horizon.Sub(now) + e.cleanupWindow
	idForClosure := accountID
	entry.timer = time.AfterFunc(delay, func() {
		e.sweep(ctx, idForClosure)
	})
}

// rearm reschedules a sweep `delay` from now. Used after a recoverable
// error in the sweep path so the account doesn't get stuck.
func (e *EphemeralManager) rearm(ctx context.Context, accountID string, delay time.Duration) {
	e.accountsLock.Lock()
	defer e.accountsLock.Unlock()
	if e.stopped {
		return
	}
	entry, ok := e.accounts[accountID]
	if !ok {
		return
	}
	idForClosure := accountID
	entry.timer = time.AfterFunc(delay, func() {
		e.sweep(ctx, idForClosure)
	})
}

// defaultInitialLoadDelay returns a random duration in
// [initialLoadMinDelay, initialLoadMaxDelay). Process-wide
// math/rand is acceptable here — the delay is purely a smoothing
// jitter, not a security primitive.
func defaultInitialLoadDelay() time.Duration {
	span := int64(initialLoadMaxDelay - initialLoadMinDelay)
	if span <= 0 {
		return initialLoadMinDelay
	}
	return initialLoadMinDelay + time.Duration(rand.Int63n(span))
}
