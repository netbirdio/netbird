package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	gproto "google.golang.org/protobuf/proto"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/internals/shared/syncmapcache"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	nbversion "github.com/netbirdio/netbird/version"
)

// syncMapSchema changes whenever the map computation or its wire encoding changes in
// a way the build version would not reveal, e.g. between two development builds.
const syncMapSchema = "1"

// configOnlySyncVersion is the first client release that keeps its posture checks on
// a SyncResponse without a network map; older clients clear them.
const configOnlySyncVersion = "0.72.3"

// maxResyncAttempts bounds the retries of the full push that follows a reuse.
const maxResyncAttempts = 3

var configOnlySyncConstraint = mustConstraint(">= " + configOnlySyncVersion)

func mustConstraint(c string) version.Constraints {
	constraint, err := version.NewConstraint(c)
	if err != nil {
		panic(fmt.Sprintf("parse version constraint %q: %v", c, err))
	}
	return constraint
}

// SyncMapGeneration identifies the build and the server configuration that shape
// network maps. A peer may reuse a map only within the generation that delivered it,
// so a deploy or a configuration change reaches every peer on its next Sync.
func SyncMapGeneration(config *nbconfig.Config, dnsDomain string) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}

	write(syncMapSchema, nbversion.NetbirdVersion(), buildRevision(), dnsDomain)
	if config != nil {
		if v := config.HighestSupportedSyncMessageVersion; v != nil {
			write(fmt.Sprint(*v))
		}
		for _, accountID := range slices.Sorted(maps.Keys(config.PerAccountHighestSupportedSyncMessageVersion)) {
			write(accountID, fmt.Sprint(config.PerAccountHighestSupportedSyncMessageVersion[accountID]))
		}
		if config.HttpConfig != nil {
			write(config.HttpConfig.AuthUserIDClaim)
		}
		if jwt := buildJWTConfig(config.HttpConfig, config.DeviceAuthorizationFlow); jwt != nil {
			b, err := gproto.MarshalOptions{Deterministic: true}.Marshal(jwt)
			if err == nil {
				write(string(b))
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil)[:16])
}

func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
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

func keyFingerprint(key wgtypes.Key) syncmapcache.KeyFingerprint {
	return syncmapcache.KeyFingerprint(key.PublicKey().String())
}

func cachePeerKey(peerKey wgtypes.Key) syncmapcache.PeerKey {
	return syncmapcache.PeerKey(peerKey.String())
}

// deliveredSerial returns the network serial a SyncResponse makes the client apply,
// and false when it carries no network map.
func deliveredSerial(resp *proto.SyncResponse) (uint64, bool) {
	if env := resp.GetNetworkMapEnvelope(); env != nil {
		full := env.GetFull()
		if full == nil {
			return 0, false
		}
		return full.GetNetwork().GetSerial(), true
	}
	if nm := resp.GetNetworkMap(); nm != nil {
		return nm.GetSerial(), true
	}
	return 0, false
}

// syncMapState is the sync map cache wiring of a server, replaced as a whole.
type syncMapState struct {
	cache  *syncmapcache.Cache
	resync *mapResyncScheduler
}

func (s *Server) mapCache() *syncmapcache.Cache {
	if st := s.syncMap.Load(); st != nil {
		return st.cache
	}
	return nil
}

// SetSyncMapCache lets Sync skip computing the map of a peer that reconnects to a
// restarted server without logging in and still holds the account's current map.
func (s *Server) SetSyncMapCache(c *syncmapcache.Cache) {
	if c == nil {
		s.syncMap.Store(nil)
		return
	}
	resync := newMapResyncScheduler(c.ResyncWindow(), c.ShuttingDown, func(ctx context.Context, accountID string, peerIDs []string) error {
		return s.networkMapController.UpdateAffectedPeers(ctx, accountID, peerIDs)
	})
	s.syncMap.Store(&syncMapState{cache: c, resync: resync})
}

// OnUpdateDropped records that an update to a peer's stream on this instance was
// dropped, so the stream never vouches for the peer's map again.
func (s *Server) OnUpdateDropped(_ context.Context, peerID string) {
	if t, ok := s.streamTrackers.Load(peerID); ok {
		t.(*deliveryTracker).dropped.Store(true)
	}
}

// invalidateMapOnLogin makes the engine that follows this Login compute its map. It
// fails the Login when reuse is enabled and the invalidation cannot be recorded.
func (s *Server) invalidateMapOnLogin(ctx context.Context, peerKey wgtypes.Key) error {
	cache := s.mapCache()
	if cache == nil {
		return nil
	}
	err := cache.OnLogin(ctx, cachePeerKey(peerKey))
	if err == nil {
		return nil
	}
	if cache.Enabled() {
		return err
	}
	log.WithContext(ctx).Warnf("failed to invalidate the delivered network map of peer %s: %v", peerKey, err)
	return nil
}

// mapReuseLookup is what a Sync read from the cache before syncing the peer.
type mapReuseLookup struct {
	seen  syncmapcache.Lookup
	read  bool
	reuse *types.MapReuse
}

// lookupMapReuse reads the peer's entry. A failed read leaves the stream out of the
// cache, so it computes the map and records nothing.
func (s *Server) lookupMapReuse(ctx context.Context, peerKey, streamKey wgtypes.Key, meta nbpeer.PeerSystemMeta) mapReuseLookup {
	cache := s.mapCache()
	if !cache.Enabled() {
		return mapReuseLookup{}
	}
	seen, err := cache.Lookup(ctx, cachePeerKey(peerKey), keyFingerprint(streamKey))
	if err != nil {
		log.WithContext(ctx).Debugf("failed to read the delivered network map of peer %s, computing it: %v", peerKey, err)
		return mapReuseLookup{}
	}
	l := mapReuseLookup{seen: seen, read: true}
	if serial, ok := seen.Serial(); ok && clientKeepsStateOnConfigOnlySync(meta.WtVersion) {
		l.reuse = &types.MapReuse{Serial: serial}
	}
	return l
}

// dropMapEntry forgets what any stream delivered to the peer.
func (s *Server) dropMapEntry(ctx context.Context, peerKey wgtypes.Key) {
	cache := s.mapCache()
	if !cache.Enabled() {
		return
	}
	if err := cache.Invalidate(ctx, cachePeerKey(peerKey)); err != nil {
		log.WithContext(ctx).Debugf("failed to invalidate the delivered network map of peer %s: %v", peerKey, err)
	}
}

// initialDelivery describes the first SyncResponse of a stream.
type initialDelivery struct {
	// serial is the network serial the response made the client apply.
	serial uint64
	// hasMap reports whether the response carried a network map.
	hasMap bool
	// key is the management key the response was encrypted with.
	key wgtypes.Key
}

// syncStream identifies one Sync stream for the cache.
type syncStream struct {
	peerKey wgtypes.Key
	// serverKey is the management key that decrypted the request; the client
	// decrypts every response of the stream with it.
	serverKey wgtypes.Key
	peerID    string
	session   syncmapcache.Session
	srv       syncSender
}

// takeOverMapEntry hands the peer's entry to this stream after its initial sync and
// returns the tracker for the updates that follow. When the stream cannot take the
// entry over, it drops the entry: a released entry must not outlive a Sync that may
// have changed what the peer holds.
func (s *Server) takeOverMapEntry(ctx context.Context, st syncStream, l mapReuseLookup, res *types.PeerSyncResult, d initialDelivery) *deliveryTracker {
	t := s.recordInitialDelivery(ctx, st, l, res, d)
	if t == nil {
		s.dropMapEntry(ctx, st.peerKey)
	}
	return t
}

// recordInitialDelivery claims the peer's entry for this stream. It returns nil when
// the stream did not take the entry over.
func (s *Server) recordInitialDelivery(ctx context.Context, st syncStream, l mapReuseLookup, res *types.PeerSyncResult, d initialDelivery) *deliveryTracker {
	cache := s.mapCache()
	if !cache.Enabled() || !l.read {
		return nil
	}

	// A response under another key than the one that decrypted the request never
	// reaches the client. An invalid peer got an empty map that must not outlive a
	// validity change nothing announces.
	if res.PeerNotValid || st.srv.Context().Err() != nil || d.key.PublicKey() != st.serverKey.PublicKey() || (!res.MapReused && !d.hasMap) {
		return nil
	}

	t := &deliveryTracker{
		cache:      cache,
		peerKey:    cachePeerKey(st.peerKey),
		session:    st.session,
		streamKey:  st.serverKey.PublicKey(),
		lastSerial: d.serial,
		lastSent:   time.Now(),
	}

	var err error
	if res.MapReused {
		err = cache.ClaimReused(ctx, t.peerKey, l.seen, st.session, keyFingerprint(st.serverKey))
		t.lastSerial, _ = l.seen.Serial()
		t.lastSent = time.Time{}
	} else {
		err = cache.ClaimDelivered(ctx, t.peerKey, l.seen, st.session, d.serial, keyFingerprint(st.serverKey))
	}
	if err != nil {
		if !errors.Is(err, syncmapcache.ErrClaimLost) {
			log.WithContext(ctx).Debugf("failed to record the initial sync of peer %s: %v", st.peerKey, err)
		}
		return nil
	}

	cache.StreamStarted()
	s.streamTrackers.Store(st.peerID, t)
	return t
}

// onSyncStreamEnded stops routing dropped-update notices to the stream's tracker.
func (s *Server) onSyncStreamEnded(peerID string, session syncmapcache.Session) {
	if t, ok := s.streamTrackers.Load(peerID); ok && t.(*deliveryTracker).session == session {
		s.streamTrackers.CompareAndDelete(peerID, t)
	}
}

// deliveryTracker records the network maps one Sync stream sent after its initial
// sync, and releases the entry when the server ends the stream on shutdown. Only
// the stream's update loop uses it, except for dropped, which the update manager
// sets.
type deliveryTracker struct {
	cache      *syncmapcache.Cache
	peerKey    syncmapcache.PeerKey
	session    syncmapcache.Session
	streamKey  wgtypes.Key
	lastSerial uint64
	// lastSent is when the stream last sent a map, zero when it sent none.
	lastSent time.Time
	// stopped is set once the stream may have left the peer behind; the entry is
	// then never released.
	stopped bool
	dropped atomic.Bool
}

// delivered records a response the stream sent with the given management key.
func (t *deliveryTracker) delivered(ctx context.Context, resp *proto.SyncResponse, key wgtypes.Key) {
	if t == nil || t.stopped {
		return
	}
	// The client decrypts with the key it fetched before opening the stream, and a
	// send during shutdown may be dropped by the hard stop.
	if t.dropped.Load() || t.cache.ShuttingDown() || key.PublicKey() != t.streamKey {
		t.stopped = true
		return
	}
	serial, ok := deliveredSerial(resp)
	if !ok {
		return
	}
	t.lastSent = time.Now()
	if serial == t.lastSerial {
		return
	}
	applied, err := t.cache.Advance(ctx, t.peerKey, t.session, serial)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to record the network map sent to peer %s: %v", t.peerKey, err)
		return
	}
	if !applied {
		t.stopped = true
		return
	}
	t.lastSerial = serial
}

// undelivered records that the stream ends with updates it never sent.
func (t *deliveryTracker) undelivered() {
	if t != nil {
		t.stopped = true
	}
}

// release marks the entry reusable when the server is ending the stream on
// shutdown and the stream left nothing behind.
func (t *deliveryTracker) release(ctx context.Context) {
	if t == nil || t.stopped || t.dropped.Load() || !t.cache.ShuttingDown() {
		return
	}
	if err := t.cache.Release(ctx, t.peerKey, t.session, t.lastSent); err != nil {
		log.WithContext(ctx).Debugf("failed to release the network map of peer %s: %v", t.peerKey, err)
	}
}

// ended uncounts the stream once it can no longer release its entry.
func (t *deliveryTracker) ended() {
	if t != nil {
		t.cache.StreamEnded()
	}
}

// resyncBatch is the peers of one account waiting for their full push.
type resyncBatch struct {
	peers   map[string]struct{}
	attempt int
}

// mapResyncScheduler pushes a full map to peers that reused theirs on Sync, after a
// random delay, so a change they missed while disconnected still reaches them. Peers
// of one account share a timer, so their account is loaded once per batch.
type mapResyncScheduler struct {
	mu       sync.Mutex
	window   time.Duration
	pending  map[string]*resyncBatch
	stopping func() bool
	push     func(ctx context.Context, accountID string, peerIDs []string) error
	delay    func(window time.Duration) time.Duration
}

func newMapResyncScheduler(window time.Duration, stopping func() bool, push func(ctx context.Context, accountID string, peerIDs []string) error) *mapResyncScheduler {
	return &mapResyncScheduler{
		window:   window,
		pending:  make(map[string]*resyncBatch),
		stopping: stopping,
		push:     push,
		delay:    rand.N[time.Duration],
	}
}

func (r *mapResyncScheduler) schedule(accountID, peerID string) {
	if r == nil {
		return
	}
	r.add(accountID, []string{peerID}, 0)
}

func (r *mapResyncScheduler) add(accountID string, peerIDs []string, attempt int) {
	if r.window <= 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if batch, ok := r.pending[accountID]; ok {
		for _, id := range peerIDs {
			batch.peers[id] = struct{}{}
		}
		return
	}

	batch := &resyncBatch{peers: make(map[string]struct{}, len(peerIDs)), attempt: attempt}
	for _, id := range peerIDs {
		batch.peers[id] = struct{}{}
	}
	r.pending[accountID] = batch
	time.AfterFunc(r.delay(r.window), func() { r.fire(accountID) })
}

func (r *mapResyncScheduler) fire(accountID string) {
	r.mu.Lock()
	batch := r.pending[accountID]
	delete(r.pending, accountID)
	r.mu.Unlock()

	if batch == nil || len(batch.peers) == 0 || r.stopping() {
		return
	}

	peerIDs := slices.Collect(maps.Keys(batch.peers))
	err := r.push(context.Background(), accountID, peerIDs)
	if err == nil {
		return
	}
	if batch.attempt+1 >= maxResyncAttempts {
		log.Warnf("gave up pushing network maps to %d peers of account %s that reused theirs: %v", len(peerIDs), accountID, err)
		return
	}
	log.Debugf("failed to push network maps to %d peers of account %s that reused theirs, retrying: %v", len(peerIDs), accountID, err)
	r.add(accountID, peerIDs, batch.attempt+1)
}
