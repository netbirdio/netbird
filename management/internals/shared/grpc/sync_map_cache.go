package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"math/rand/v2"
	"runtime/debug"
	"slices"
	"sync"
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

// SetSyncMapCache lets Sync skip computing the map of a peer that reconnects
// without logging in and still holds the account's current map. Call it before the
// server starts serving.
func (s *Server) SetSyncMapCache(c *syncmapcache.Cache) {
	s.syncMapCache = c
	if c == nil {
		return
	}
	s.mapResync = newMapResyncScheduler(c.ResyncWindow(), c.ShuttingDown, func(ctx context.Context, accountID string, peerIDs []string) {
		reason := types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationRefresh}
		if err := s.networkMapController.BufferUpdateAffectedPeers(ctx, accountID, peerIDs, reason); err != nil {
			log.WithContext(ctx).Warnf("failed to push network maps to %d peers that reused theirs: %v", len(peerIDs), err)
		}
	})
}

// OnUpdateDropped invalidates the delivered map of a peer whose update was dropped
// on its way to the peer's stream on this instance.
func (s *Server) OnUpdateDropped(ctx context.Context, peerID string) {
	if s.syncMapCache == nil {
		return
	}
	peerKey, ok := s.streamPeerKeys.Load(peerID)
	if !ok {
		return
	}
	s.syncMapCache.InvalidateAsync(ctx, peerKey.(string))
}

// invalidateMapOnLogin makes the engine that follows this Login compute its map. It
// fails the Login when reuse is enabled and the invalidation cannot be recorded.
func (s *Server) invalidateMapOnLogin(ctx context.Context, peerKey wgtypes.Key) error {
	if s.syncMapCache == nil {
		return nil
	}
	err := s.syncMapCache.OnLogin(ctx, peerKey.String())
	if err == nil {
		return nil
	}
	if s.syncMapCache.Enabled() {
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
	if !s.syncMapCache.Enabled() {
		return mapReuseLookup{}
	}
	seen, err := s.syncMapCache.Lookup(ctx, peerKey.String(), keyFingerprint(streamKey))
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

// recordInitialDelivery hands the peer's entry to this stream after its initial
// sync and returns the tracker for the updates that follow, or nil when the
// stream records nothing.
func (s *Server) recordInitialDelivery(ctx context.Context, st syncStream, l mapReuseLookup, res *types.PeerSyncResult, d initialDelivery) *deliveryTracker {
	if !s.syncMapCache.Enabled() || !l.read {
		return nil
	}
	s.streamPeerKeys.Store(st.peerID, st.peerKey.String())

	t := &deliveryTracker{
		cache:      s.syncMapCache,
		peerKey:    st.peerKey.String(),
		session:    st.session,
		streamKey:  st.serverKey.PublicKey(),
		lastSerial: d.serial,
	}

	// A response under another key than the one that decrypted the request never
	// reaches the client. An invalid peer got an empty map that must not outlive a
	// validity change nothing announces.
	if res.PeerNotValid || st.srv.Context().Err() != nil || d.key.PublicKey() != t.streamKey || (!res.MapReused && !d.hasMap) {
		t.invalidate(ctx, "the initial sync cannot be reused")
		return nil
	}

	fingerprint := keyFingerprint(st.serverKey)
	var err error
	if res.MapReused {
		err = s.syncMapCache.ClaimReused(ctx, t.peerKey, l.seen, st.session, fingerprint)
		if serial, ok := l.seen.Serial(); ok {
			t.lastSerial = serial
		}
	} else {
		err = s.syncMapCache.ClaimDelivered(ctx, t.peerKey, l.seen, st.session, d.serial, fingerprint)
	}
	if err != nil {
		t.invalidate(ctx, fmt.Sprintf("record the initial sync: %v", err))
		return nil
	}
	return t
}

// onSyncStreamEnded forgets what the stream delivered, unless the process is stopping:
// then the peer reconnects to another instance holding exactly what it was sent.
func (s *Server) onSyncStreamEnded(ctx context.Context, peer *nbpeer.Peer, streamStart time.Time) {
	if s.syncMapCache == nil {
		return
	}
	s.streamPeerKeys.Delete(peer.ID)
	if !s.syncMapCache.Enabled() || s.syncMapCache.ShuttingDown() {
		return
	}
	if err := s.syncMapCache.InvalidateSession(ctx, peer.Key, syncmapcache.Session(streamStart.UnixNano())); err != nil {
		log.WithContext(ctx).Warnf("failed to invalidate the delivered network map of peer %s: %v", peer.Key, err)
	}
}

// deliveryTracker records the network maps one Sync stream delivered after its
// initial sync. Only the stream's update loop uses it.
type deliveryTracker struct {
	cache      *syncmapcache.Cache
	peerKey    string
	session    syncmapcache.Session
	streamKey  wgtypes.Key
	lastSerial uint64
	stopped    bool
}

// delivered records a response the stream sent with the given management key.
func (t *deliveryTracker) delivered(ctx context.Context, resp *proto.SyncResponse, key wgtypes.Key) {
	if t == nil || t.stopped {
		return
	}
	if key.PublicKey() != t.streamKey {
		t.invalidate(ctx, "the management key changed under the stream")
		return
	}
	serial, ok := deliveredSerial(resp)
	if !ok || serial == t.lastSerial {
		return
	}
	if err := t.cache.Advance(ctx, t.peerKey, t.session, serial); err != nil {
		log.WithContext(ctx).Debugf("failed to record the network map delivered to peer %s: %v", t.peerKey, err)
		return
	}
	t.lastSerial = serial
}

// undelivered records that the stream ends with updates it never sent.
func (t *deliveryTracker) undelivered(ctx context.Context) {
	if t == nil || t.stopped {
		return
	}
	t.invalidate(ctx, "the stream ended with undelivered updates")
}

func (t *deliveryTracker) invalidate(ctx context.Context, reason string) {
	t.stopped = true
	if err := t.cache.Invalidate(ctx, t.peerKey); err != nil {
		log.WithContext(ctx).Warnf("failed to invalidate the delivered network map of peer %s (%s): %v", t.peerKey, reason, err)
		return
	}
	log.WithContext(ctx).Debugf("invalidated the delivered network map of peer %s: %s", t.peerKey, reason)
}

// mapResyncScheduler pushes a full map to peers that reused theirs on Sync, after a
// random delay, so a change they missed while disconnected still reaches them. Peers
// of one account share a timer, so their account is loaded once per batch.
type mapResyncScheduler struct {
	mu       sync.Mutex
	window   time.Duration
	pending  map[string]map[string]struct{}
	stopping func() bool
	push     func(ctx context.Context, accountID string, peerIDs []string)
}

func newMapResyncScheduler(window time.Duration, stopping func() bool, push func(ctx context.Context, accountID string, peerIDs []string)) *mapResyncScheduler {
	return &mapResyncScheduler{
		window:   window,
		pending:  make(map[string]map[string]struct{}),
		stopping: stopping,
		push:     push,
	}
}

func (r *mapResyncScheduler) schedule(accountID, peerID string) {
	if r == nil || r.window <= 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if peers, ok := r.pending[accountID]; ok {
		peers[peerID] = struct{}{}
		return
	}
	r.pending[accountID] = map[string]struct{}{peerID: {}}

	delay := rand.N(r.window)
	time.AfterFunc(delay, func() { r.fire(accountID) })
}

func (r *mapResyncScheduler) fire(accountID string) {
	r.mu.Lock()
	peers := r.pending[accountID]
	delete(r.pending, accountID)
	r.mu.Unlock()

	if len(peers) == 0 || r.stopping() {
		return
	}
	r.push(context.Background(), accountID, slices.Collect(maps.Keys(peers)))
}
