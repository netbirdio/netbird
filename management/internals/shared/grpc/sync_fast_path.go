package grpc

import (
	"context"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	integrationsConfig "github.com/netbirdio/management-integrations/integrations/config"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// peerGroupFetcher returns the group IDs a peer belongs to. It is a dependency
// of buildFastPathResponse so tests can inject a stub without a real store.
type peerGroupFetcher func(ctx context.Context, accountID, peerID string) ([]string, error)

// peerSyncEntry records what the server last delivered to a peer on Sync so we
// can decide whether the next Sync can skip the full network map computation.
// It also carries the minimum peer/auth metadata needed to run the fast path
// without a DB round-trip on cache hit.
type peerSyncEntry struct {
	// Serial is the NetworkMap.Serial the server last included in a full map
	// delivered to this peer.
	Serial uint64
	// MetaHash is the metaHash() value of the peer metadata at the time of that
	// delivery, used to detect a meta change on reconnect.
	MetaHash uint64
	// AccountID is the peer's account ID. Cached so the Sync hot path can skip
	// GetPeerAuthInfo on cache hit.
	AccountID string
	// PeerID is the peer's internal ID, needed for network-map subscription
	// and update-channel routing.
	PeerID string
	// PeerKey mirrors the cache key (peer's wireguard pubkey) so the peer
	// snapshot carries everything required by cancelPeerRoutines without a
	// second store lookup.
	PeerKey string
	// Ephemeral is the peer's ephemeral flag, used by EphemeralPeersManager
	// on subscribe/unsubscribe.
	Ephemeral bool
	// HasUser is true if the peer is user-owned (peer.UserID != ""). Used in
	// place of GetUserIDByPeerKey's result to drive the loginFilter gate on
	// cache hit.
	HasUser bool
}

// IsComplete reports whether the entry has every field the pure-cache fast
// path needs. Entries written by older code (before step 2) will carry only
// Serial and MetaHash and must fall back to the slow path so the cache is
// repopulated with the full shape.
func (e peerSyncEntry) IsComplete() bool {
	return e.AccountID != "" && e.PeerID != "" && e.PeerKey != ""
}

// PeerSnapshot reconstructs the minimum *nbpeer.Peer needed by
// OnPeerConnectedWithPeer, EphemeralPeersManager, handleUpdates,
// cancelPeerRoutines, and buildFastPathResponse.
func (e peerSyncEntry) PeerSnapshot() *nbpeer.Peer {
	return &nbpeer.Peer{
		ID:        e.PeerID,
		Key:       e.PeerKey,
		AccountID: e.AccountID,
		Ephemeral: e.Ephemeral,
	}
}

// lookupPeerAuthFromCache checks whether the peer-sync cache holds a complete
// entry for this peer with a matching metaHash, so the Sync handler can skip
// the pre-fast-path GetPeerAuthInfo store read. Returns hit=false whenever
// the fast path is disabled, the peer is Android, the cache is empty, the
// entry is from an older shape without snapshot fields, or metaHash differs.
func (s *Server) lookupPeerAuthFromCache(peerPubKey string, incomingMetaHash uint64, goOS string) (peerSyncEntry, bool) {
	if s.peerSerialCache == nil {
		return peerSyncEntry{}, false
	}
	if !s.fastPathFlag.Enabled() {
		return peerSyncEntry{}, false
	}
	if strings.EqualFold(goOS, "android") {
		return peerSyncEntry{}, false
	}
	entry, hit := s.peerSerialCache.Get(peerPubKey)
	if !hit || !entry.IsComplete() {
		return peerSyncEntry{}, false
	}
	if entry.MetaHash != incomingMetaHash {
		return peerSyncEntry{}, false
	}
	return entry, true
}

// shouldSkipNetworkMap reports whether a Sync request from this peer can be
// answered with a lightweight NetbirdConfig-only response instead of a full
// map computation. All conditions must hold:
//   - the peer is not Android (Android's GrpcClient.GetNetworkMap errors on nil map)
//   - the cache holds an entry for this peer
//   - the cached serial matches the current account serial
//   - the cached meta hash matches the incoming meta hash
//   - the cached serial is non-zero (guard against uninitialised entries)
func shouldSkipNetworkMap(goOS string, hit bool, cached peerSyncEntry, currentSerial, incomingMetaHash uint64) bool {
	if strings.EqualFold(goOS, "android") {
		return false
	}
	if !hit {
		return false
	}
	if cached.Serial == 0 {
		return false
	}
	if cached.Serial != currentSerial {
		return false
	}
	if cached.MetaHash != incomingMetaHash {
		return false
	}
	return true
}

// extraSettingsFetcher is the dependency used by buildFastPathResponse to
// obtain ExtraSettings for the peer's account. Matches the shape of the
// method on settings.Manager but as a plain function so production callers
// can wrap it with a cache and tests can inject a stub.
type extraSettingsFetcher func(ctx context.Context, accountID string) (*nbtypes.ExtraSettings, error)

// buildFastPathResponse constructs a SyncResponse containing only NetbirdConfig
// with fresh TURN/Relay tokens, mirroring the shape used by
// TimeBasedAuthSecretsManager when pushing token refreshes. The response omits
// NetworkMap, PeerConfig, Checks and RemotePeers; the client keeps its existing
// state and only refreshes its control-plane credentials.
func buildFastPathResponse(
	ctx context.Context,
	cfg *nbconfig.Config,
	secrets SecretsManager,
	fetchExtraSettings extraSettingsFetcher,
	fetchGroups peerGroupFetcher,
	peer *nbpeer.Peer,
) *proto.SyncResponse {
	var turnToken *Token
	if cfg != nil && cfg.TURNConfig != nil && cfg.TURNConfig.TimeBasedCredentials {
		if t, err := secrets.GenerateTurnToken(); err == nil {
			turnToken = t
		} else {
			log.WithContext(ctx).Warnf("fast path: generate TURN token: %v", err)
		}
	}

	var relayToken *Token
	if cfg != nil && cfg.Relay != nil && len(cfg.Relay.Addresses) > 0 {
		if t, err := secrets.GenerateRelayToken(); err == nil {
			relayToken = t
		} else {
			log.WithContext(ctx).Warnf("fast path: generate relay token: %v", err)
		}
	}

	var extraSettings *nbtypes.ExtraSettings
	if fetchExtraSettings != nil {
		if es, err := fetchExtraSettings(ctx, peer.AccountID); err != nil {
			log.WithContext(ctx).Debugf("fast path: get extra settings: %v", err)
		} else {
			extraSettings = es
		}
	}

	nbConfig := toNetbirdConfig(cfg, turnToken, relayToken, extraSettings)

	var peerGroups []string
	if fetchGroups != nil {
		if ids, err := fetchGroups(ctx, peer.AccountID, peer.ID); err != nil {
			log.WithContext(ctx).Debugf("fast path: get peer group ids: %v", err)
		} else {
			peerGroups = ids
		}
	}

	extendStart := time.Now()
	nbConfig = integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)
	log.WithContext(ctx).Debugf("fast path: ExtendNetBirdConfig took %s", time.Since(extendStart))

	return &proto.SyncResponse{NetbirdConfig: nbConfig}
}

// fetchExtraSettings returns a cached ExtraSettings when available, falling
// back to the settings manager on miss. Populates the cache on miss so
// subsequent fast-path Syncs hit it.
func (s *Server) fetchExtraSettings(ctx context.Context, accountID string) (*nbtypes.ExtraSettings, error) {
	if es, ok := s.extraSettingsCache.get(accountID); ok {
		log.WithContext(ctx).Debugf("fast path: GetExtraSettings skipped (cache hit)")
		return es, nil
	}

	start := time.Now()
	es, err := s.settingsManager.GetExtraSettings(ctx, accountID)
	if err != nil {
		return nil, err
	}
	log.WithContext(ctx).Debugf("fast path: GetExtraSettings took %s", time.Since(start))
	s.extraSettingsCache.set(accountID, es)
	return es, nil
}

// tryFastPathSync decides whether the current Sync can be answered with a
// lightweight NetbirdConfig-only response. When the fast path runs, it takes
// over the whole Sync handler (MarkPeerConnected, send, OnPeerConnected,
// SetupRefresh, handleUpdates) and the returned took value is true.
//
// When took is true the caller must return the accompanying err. When took is
// false the caller falls through to the existing slow path.
func (s *Server) tryFastPathSync(
	ctx context.Context,
	reqStart, syncStart time.Time,
	accountID string,
	peerKey wgtypes.Key,
	peerMeta nbpeer.PeerSystemMeta,
	realIP net.IP,
	peerMetaHash uint64,
	srv proto.ManagementService_SyncServer,
	unlock *func(),
) (took bool, err error) {
	if s.peerSerialCache == nil {
		return false, nil
	}
	if !s.fastPathFlag.Enabled() {
		return false, nil
	}
	if strings.EqualFold(peerMeta.GoOS, "android") {
		return false, nil
	}

	networkStart := time.Now()
	network, err := s.accountManager.GetStore().GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Debugf("fast path: lookup account network: %v", err)
		return false, nil
	}
	log.WithContext(ctx).Debugf("fast path: initial GetAccountNetwork took %s", time.Since(networkStart))

	eligibilityStart := time.Now()
	cached, hit := s.peerSerialCache.Get(peerKey.String())
	if !shouldSkipNetworkMap(peerMeta.GoOS, hit, cached, network.CurrentSerial(), peerMetaHash) {
		log.WithContext(ctx).Debugf("fast path: eligibility check (miss) took %s", time.Since(eligibilityStart))
		return false, nil
	}
	log.WithContext(ctx).Debugf("fast path: eligibility check (hit) took %s", time.Since(eligibilityStart))

	var cachedPeer *nbpeer.Peer
	if cached.IsComplete() {
		cachedPeer = cached.PeerSnapshot()
	}
	peer, updates, committed := s.commitFastPath(ctx, accountID, peerKey, realIP, syncStart, cachedPeer)
	if !committed {
		return false, nil
	}

	// Upgrade the cache only when we had to fetch the peer from the store
	// this Sync. In the steady state the cached snapshot lacks UserID (not
	// part of PeerSnapshot), so rewriting from it would flip HasUser to
	// false and corrupt the entry. A cache-served peer also means the
	// entry is already in the full shape, so there's nothing to upgrade.
	upgradeCache := cachedPeer == nil

	return true, s.runFastPathSync(ctx, reqStart, syncStart, accountID, peerKey, peer, updates, cached.Serial, peerMetaHash, upgradeCache, srv, unlock)
}

// commitFastPath subscribes the peer to network-map updates and marks it
// connected. When cachedPeer is non-nil (cache hit with a complete entry),
// the expensive GetPeerByPeerPubKey store call is skipped and the cached
// snapshot is used instead.
//
// It relies on the same eventual-consistency guarantee as the slow path: a
// concurrent writer's broadcast may race the subscription, but any subsequent
// serial change reaches the subscribed peer via its update channel, and a
// reconnect with a stale cached serial falls through to the slow path on the
// next Sync. Returns committed=false on any failure that should not block
// the slow path from running.
func (s *Server) commitFastPath(
	ctx context.Context,
	accountID string,
	peerKey wgtypes.Key,
	realIP net.IP,
	syncStart time.Time,
	cachedPeer *nbpeer.Peer,
) (*nbpeer.Peer, chan *network_map.UpdateMessage, bool) {
	commitStart := time.Now()
	defer func() {
		log.WithContext(ctx).Debugf("fast path: commitFastPath took %s", time.Since(commitStart))
	}()

	var peer *nbpeer.Peer
	if cachedPeer != nil {
		peer = cachedPeer
		log.WithContext(ctx).Debugf("fast path: GetPeerByPeerPubKey skipped (cache hit)")
	} else {
		getPeerStart := time.Now()
		p, err := s.accountManager.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.String())
		if err != nil {
			log.WithContext(ctx).Debugf("fast path: lookup peer %s: %v", peerKey.String(), err)
			return nil, nil, false
		}
		log.WithContext(ctx).Debugf("fast path: GetPeerByPeerPubKey took %s", time.Since(getPeerStart))
		peer = p
	}

	onConnectedStart := time.Now()
	updates, err := s.networkMapController.OnPeerConnectedWithPeer(ctx, accountID, peer)
	if err != nil {
		log.WithContext(ctx).Debugf("fast path: notify peer connected for %s: %v", peerKey.String(), err)
		return nil, nil, false
	}
	log.WithContext(ctx).Debugf("fast path: OnPeerConnectedWithPeer took %s", time.Since(onConnectedStart))

	s.markPeerConnectedAsync(peerKey.String(), realIP, accountID, syncStart)

	return peer, updates, true
}

// markPeerConnectedAsync fires MarkPeerConnected in a detached goroutine so
// the Sync hot path does not wait on a DB write that can spike into the
// multi-second range under contention. LastSeen becomes eventually-consistent
// by at most one write; the peer's next Sync or the per-peer expiration
// routines correct any drift. Concurrent fast-path Syncs for the same peer
// coalesce to a single background write via the inflight map.
func (s *Server) markPeerConnectedAsync(peerKey string, realIP net.IP, accountID string, syncStart time.Time) {
	if _, loaded := s.inflightMarkPeerConnected.LoadOrStore(peerKey, struct{}{}); loaded {
		log.Debugf("fast path: async MarkPeerConnected for %s coalesced (already in flight)", peerKey)
		return
	}
	go func() {
		defer s.inflightMarkPeerConnected.Delete(peerKey)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		start := time.Now()
		if err := s.accountManager.MarkPeerConnected(ctx, peerKey, true, realIP, accountID, syncStart); err != nil {
			log.Warnf("fast path: async MarkPeerConnected for %s: %v", peerKey, err)
			return
		}
		log.Debugf("fast path: async MarkPeerConnected for %s took %s", peerKey, time.Since(start))
	}()
}

// runFastPathSync executes the fast path: send the lean response, kick off
// token refresh, release the per-peer lock, then block on handleUpdates until
// the stream is closed. Peer lookup and subscription have already been
// performed by commitFastPath so the race between eligibility check and
// subscription is already closed.
func (s *Server) runFastPathSync(
	ctx context.Context,
	reqStart, syncStart time.Time,
	accountID string,
	peerKey wgtypes.Key,
	peer *nbpeer.Peer,
	updates chan *network_map.UpdateMessage,
	serial uint64,
	peerMetaHash uint64,
	upgradeCache bool,
	srv proto.ManagementService_SyncServer,
	unlock *func(),
) error {
	sendStart := time.Now()
	if err := s.sendFastPathResponse(ctx, peerKey, peer, srv); err != nil {
		log.WithContext(ctx).Debugf("fast path: send response for peer %s: %v", peerKey.String(), err)
		s.syncSem.Add(-1)
		s.cancelPeerRoutinesWithoutLock(ctx, accountID, peer, syncStart)
		return err
	}
	log.WithContext(ctx).Debugf("fast path: sendFastPathResponse took %s", time.Since(sendStart))

	// Upgrade a legacy-shape cache entry (Serial + MetaHash only, pre step 2)
	// to the full shape so the next Sync's lookupPeerAuthFromCache +
	// commitFastPath can actually short-circuit the pre-fast-path
	// GetPeerAuthInfo and GetPeerByPeerPubKey. Only runs when the peer was
	// freshly fetched from the store this Sync — rewriting from a cached
	// snapshot would lose HasUser because PeerSnapshot doesn't carry UserID.
	if upgradeCache {
		s.writePeerSyncEntry(peerKey.String(), serial, peerMetaHash, peer)
	}

	s.secretsManager.SetupRefresh(ctx, accountID, peer.ID)

	if unlock != nil && *unlock != nil {
		(*unlock)()
		*unlock = nil
	}

	if s.appMetrics != nil {
		s.appMetrics.GRPCMetrics().CountSyncRequestDuration(time.Since(reqStart), accountID)
	}
	log.WithContext(ctx).Debugf("Sync (fast path) took %s", time.Since(reqStart))

	s.syncSem.Add(-1)

	return s.handleUpdates(ctx, accountID, peerKey, peer, peerMetaHash, updates, srv, syncStart)
}

// sendFastPathResponse builds a NetbirdConfig-only SyncResponse, encrypts it
// with the peer's WireGuard key and pushes it over the stream.
func (s *Server) sendFastPathResponse(ctx context.Context, peerKey wgtypes.Key, peer *nbpeer.Peer, srv proto.ManagementService_SyncServer) error {
	resp := buildFastPathResponse(ctx, s.config, s.secretsManager, s.fetchExtraSettings, s.fetchPeerGroups, peer)

	key, err := s.secretsManager.GetWGKey()
	if err != nil {
		return status.Errorf(codes.Internal, "failed getting server key")
	}

	body, err := encryption.EncryptMessage(peerKey, key, resp)
	if err != nil {
		return status.Errorf(codes.Internal, "error encrypting fast-path sync response")
	}

	if err := srv.Send(&proto.EncryptedMessage{
		WgPubKey: key.PublicKey().String(),
		Body:     body,
	}); err != nil {
		log.WithContext(ctx).Errorf("failed sending fast-path sync response: %v", err)
		return status.Errorf(codes.Internal, "error handling request")
	}
	return nil
}

// fetchPeerGroups returns a cached list of group IDs for the peer when
// available, falling back to the account manager's store on miss. Populates
// the cache on miss so subsequent fast-path Syncs hit it.
func (s *Server) fetchPeerGroups(ctx context.Context, accountID, peerID string) ([]string, error) {
	if ids, ok := s.peerGroupsCache.get(peerID); ok {
		log.WithContext(ctx).Debugf("fast path: GetPeerGroupIDs skipped (cache hit)")
		return ids, nil
	}

	start := time.Now()
	ids, err := s.accountManager.GetStore().GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, err
	}
	log.WithContext(ctx).Debugf("fast path: GetPeerGroupIDs took %s", time.Since(start))
	s.peerGroupsCache.set(peerID, ids)
	return ids, nil
}

// recordPeerSyncEntry writes the serial just delivered to this peer so a
// subsequent reconnect can take the fast path. Called after the slow path's
// sendInitialSync has pushed a full map. A nil cache disables the fast path.
// peer is required so the cached entry carries the snapshot fields the
// pure-cache fast path needs (AccountID, PeerID, Key, Ephemeral, HasUser).
func (s *Server) recordPeerSyncEntry(peerKey string, netMap *nbtypes.NetworkMap, peerMetaHash uint64, peer *nbpeer.Peer) {
	if netMap == nil || netMap.Network == nil {
		return
	}
	s.writePeerSyncEntry(peerKey, netMap.Network.CurrentSerial(), peerMetaHash, peer)
}

// recordPeerSyncEntryFromUpdate is the sendUpdate equivalent of
// recordPeerSyncEntry: it extracts the serial from a streamed NetworkMap update
// so the cache stays in sync with what the peer most recently received.
func (s *Server) recordPeerSyncEntryFromUpdate(peerKey string, update *network_map.UpdateMessage, peerMetaHash uint64, peer *nbpeer.Peer) {
	if update == nil || update.Update == nil || update.Update.NetworkMap == nil {
		return
	}
	s.writePeerSyncEntry(peerKey, update.Update.NetworkMap.GetSerial(), peerMetaHash, peer)
}

// writePeerSyncEntry is the common cache write used by every path that
// delivers state to a peer: the slow-path sendInitialSync, streamed
// NetworkMap updates, and the fast path itself. Writing from the fast path
// upgrades legacy-shape entries (Serial + MetaHash only, pre step 2) to the
// full shape on the next successful Sync so subsequent cache hits can
// actually short-circuit GetPeerAuthInfo and GetPeerByPeerPubKey.
func (s *Server) writePeerSyncEntry(peerKey string, serial, peerMetaHash uint64, peer *nbpeer.Peer) {
	if s.peerSerialCache == nil {
		return
	}
	if !s.fastPathFlag.Enabled() {
		return
	}
	if serial == 0 {
		return
	}
	s.peerSerialCache.Set(peerKey, newPeerSyncEntry(serial, peerMetaHash, peer))
}

// newPeerSyncEntry builds a cache entry with every field the pure-cache
// fast path needs. peer may be nil (very old call sites), in which case the
// entry is written without the snapshot fields and will fail IsComplete().
func newPeerSyncEntry(serial, metaHash uint64, peer *nbpeer.Peer) peerSyncEntry {
	entry := peerSyncEntry{
		Serial:   serial,
		MetaHash: metaHash,
	}
	if peer != nil {
		entry.AccountID = peer.AccountID
		entry.PeerID = peer.ID
		entry.PeerKey = peer.Key
		entry.Ephemeral = peer.Ephemeral
		entry.HasUser = peer.UserID != ""
	}
	return entry
}

// invalidatePeerSyncEntry is called after a successful Login so the next Sync
// is guaranteed to deliver a full map, picking up whatever changed in the
// login (SSH key rotation, approval state, user binding, etc.).
func (s *Server) invalidatePeerSyncEntry(peerKey string) {
	if s.peerSerialCache == nil {
		return
	}
	s.peerSerialCache.Delete(peerKey)
}
