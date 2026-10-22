package grpc

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/types"
	nbversion "github.com/netbirdio/netbird/version"
)

const (
	// EnvSyncMapCacheEnabled lets a peer that reconnects with Sync, without logging in
	// first, skip the network map computation and keep the map it already holds.
	EnvSyncMapCacheEnabled = "NB_SYNC_MAP_CACHE_ENABLED"
	// EnvSyncMapCacheResyncWindow is how long a peer that resumed without a map waits,
	// at most, for a full one.
	EnvSyncMapCacheResyncWindow = "NB_SYNC_MAP_CACHE_RESYNC_WINDOW"
)

const (
	syncMapCacheKeyPrefix = "nb:syncmap:"
	// syncMapCacheTTL bounds how long a peer can keep reconnecting without a full map.
	syncMapCacheTTL = 24 * time.Hour
	// configOnlySyncVersion is the first client release that keeps its posture checks
	// on a SyncResponse without a network map; older clients clear them.
	configOnlySyncVersion = "0.72.3"

	defaultResyncWindow = 10 * time.Minute
	maxResyncWindow     = time.Hour
	// maxResyncAttempts bounds the pushes tried for one batch before giving up.
	maxResyncAttempts = 3
)

var configOnlySyncConstraint = mustConstraint(">= " + configOnlySyncVersion)

func mustConstraint(c string) version.Constraints {
	constraint, err := version.NewConstraint(c)
	if err != nil {
		panic(fmt.Sprintf("parse version constraint %q: %v", c, err))
	}
	return constraint
}

// SyncMapCache records, per peer key, the network serial of the last full map sent
// since the peer's last Login.
type SyncMapCache struct {
	store   nbcache.Store
	enabled bool
}

// NewSyncMapCache returns a sync map cache over the shared cache store. Only Sync reads
// and writes it when EnvSyncMapCacheEnabled is set, but Login always clears the peer's
// entry, so an instance with the flag off never leaves a stale one for the others.
func NewSyncMapCache(cacheStore nbcache.Store) *SyncMapCache {
	return &SyncMapCache{store: cacheStore, enabled: syncMapCacheEnabledByEnv()}
}

func syncMapCacheEnabledByEnv() bool {
	val := os.Getenv(EnvSyncMapCacheEnabled)
	if val == "" {
		return false
	}
	enabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvSyncMapCacheEnabled, err)
		return false
	}
	return enabled
}

func syncMapCacheKey(peerKey string) string {
	return syncMapCacheKeyPrefix + peerKey
}

// canSkipMap reports whether the peer received a full map since its last Login and its
// client keeps that map when a SyncResponse carries none.
func (c *SyncMapCache) canSkipMap(ctx context.Context, peerKey, clientVersion string) bool {
	if c == nil || !c.enabled || !clientKeepsStateOnConfigOnlySync(clientVersion) {
		return false
	}
	_, err := c.store.Get(ctx, syncMapCacheKey(peerKey))
	if err == nil {
		return true
	}
	if !errors.Is(err, &store.NotFound{}) {
		log.WithContext(ctx).Debugf("failed to read the sync map cache of peer %s: %v", peerKey, err)
	}
	return false
}

// mapSent records that the peer was sent a full map with the given network serial.
func (c *SyncMapCache) mapSent(ctx context.Context, peerKey string, serial uint64) {
	if c == nil || !c.enabled {
		return
	}
	value := strconv.FormatUint(serial, 10)
	if err := c.store.Set(ctx, syncMapCacheKey(peerKey), value, store.WithExpiration(syncMapCacheTTL)); err != nil {
		log.WithContext(ctx).Debugf("failed to record the network map sent to peer %s: %v", peerKey, err)
	}
}

// forget makes the peer's next Sync compute its map.
func (c *SyncMapCache) forget(ctx context.Context, peerKey string) error {
	if c == nil {
		return nil
	}
	if err := c.store.Delete(ctx, syncMapCacheKey(peerKey)); err != nil {
		return fmt.Errorf("delete sync map cache entry: %w", err)
	}
	return nil
}

func sentMapSerial(netMap *types.NetworkMap) uint64 {
	if netMap == nil || netMap.Network == nil {
		return 0
	}
	return netMap.Network.CurrentSerial()
}

// clientKeepsStateOnConfigOnlySync reports whether a client of this version keeps
// its network map and posture checks when a SyncResponse carries no map.
func clientKeepsStateOnConfigOnlySync(clientVersion string) bool {
	if nbversion.IsDevelopmentVersion(clientVersion) {
		return true
	}
	v, err := version.NewVersion(clientVersion)
	if err != nil {
		return false
	}
	return configOnlySyncConstraint.Check(v)
}

// syncMapResyncWindow reads EnvSyncMapCacheResyncWindow. The resync cannot be turned
// off, since it is what bounds how long a peer that resumed can miss a change.
func syncMapResyncWindow() time.Duration {
	val := os.Getenv(EnvSyncMapCacheResyncWindow)
	if val == "" {
		return defaultResyncWindow
	}
	window, err := time.ParseDuration(val)
	if err != nil || window <= 0 {
		log.Warnf("invalid %s %q, using %s", EnvSyncMapCacheResyncWindow, val, defaultResyncWindow)
		return defaultResyncWindow
	}
	return min(window, maxResyncWindow)
}

// resyncBatch is the peers of one account waiting for their full push.
type resyncBatch struct {
	peers   map[string]struct{}
	attempt int
}

// mapResyncScheduler pushes a full map to the peers that resumed without one, so a
// change they missed while disconnected still reaches them. Each account is pushed at
// most once per window, at a tick derived from its ID: every instance pushes the
// account's peers at the same time, and accounts spread evenly over the window.
type mapResyncScheduler struct {
	mu      sync.Mutex
	window  time.Duration
	pending map[string]*resyncBatch
	push    func(ctx context.Context, accountID string, peerIDs []string) error
	now     func() time.Time
	after   func(d time.Duration, f func())
}

func newMapResyncScheduler(window time.Duration, push func(ctx context.Context, accountID string, peerIDs []string) error) *mapResyncScheduler {
	return &mapResyncScheduler{
		window:  window,
		pending: make(map[string]*resyncBatch),
		push:    push,
		now:     time.Now,
		after:   func(d time.Duration, f func()) { time.AfterFunc(d, f) },
	}
}

func (r *mapResyncScheduler) schedule(accountID, peerID string) {
	if r != nil {
		r.add(accountID, []string{peerID}, 0)
	}
}

func (r *mapResyncScheduler) add(accountID string, peerIDs []string, attempt int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	batch, ok := r.pending[accountID]
	if !ok {
		batch = &resyncBatch{peers: make(map[string]struct{}, len(peerIDs)), attempt: attempt}
		r.pending[accountID] = batch
		r.after(untilResyncTick(accountID, r.window, r.now()), func() { r.fire(accountID) })
	}
	for _, id := range peerIDs {
		batch.peers[id] = struct{}{}
	}
}

func (r *mapResyncScheduler) fire(accountID string) {
	r.mu.Lock()
	batch := r.pending[accountID]
	delete(r.pending, accountID)
	r.mu.Unlock()

	if batch == nil {
		return
	}

	peerIDs := slices.Collect(maps.Keys(batch.peers))
	err := r.push(context.Background(), accountID, peerIDs)
	if err == nil {
		return
	}
	if batch.attempt+1 >= maxResyncAttempts {
		log.Warnf("gave up pushing network maps to %d peers of account %s that resumed without one: %v", len(peerIDs), accountID, err)
		return
	}
	log.Debugf("failed to push network maps to %d peers of account %s that resumed without one, retrying: %v", len(peerIDs), accountID, err)
	r.add(accountID, peerIDs, batch.attempt+1)
}

// untilResyncTick returns the time from now to the account's next resync tick, in
// (0, window]. Ticks fall every window at an offset hashed from the account ID.
func untilResyncTick(accountID string, window time.Duration, now time.Time) time.Duration {
	h := fnv.New64a()
	_, _ = h.Write([]byte(accountID))
	offset := int64(h.Sum64() % uint64(window))
	elapsed := (now.UnixNano() - offset) % int64(window)
	if elapsed < 0 {
		elapsed += int64(window)
	}
	return window - time.Duration(elapsed)
}
