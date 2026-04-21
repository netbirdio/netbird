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
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// peerGroupFetcher returns the group IDs a peer belongs to. It is a dependency
// of buildFastPathResponse so tests can inject a stub without a real store.
type peerGroupFetcher func(ctx context.Context, accountID, peerID string) ([]string, error)

// peerSyncEntry records what the server last delivered to a peer on Sync so we
// can decide whether the next Sync can skip the full network map computation.
type peerSyncEntry struct {
	// Serial is the NetworkMap.Serial the server last included in a full map
	// delivered to this peer.
	Serial uint64
	// MetaHash is the metaHash() value of the peer metadata at the time of that
	// delivery, used to detect a meta change on reconnect.
	MetaHash uint64
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

// buildFastPathResponse constructs a SyncResponse containing only NetbirdConfig
// with fresh TURN/Relay tokens, mirroring the shape used by
// TimeBasedAuthSecretsManager when pushing token refreshes. The response omits
// NetworkMap, PeerConfig, Checks and RemotePeers; the client keeps its existing
// state and only refreshes its control-plane credentials.
func buildFastPathResponse(
	ctx context.Context,
	cfg *nbconfig.Config,
	secrets SecretsManager,
	settingsMgr settings.Manager,
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
	if es, err := settingsMgr.GetExtraSettings(ctx, peer.AccountID); err != nil {
		log.WithContext(ctx).Debugf("fast path: get extra settings: %v", err)
	} else {
		extraSettings = es
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

	nbConfig = integrationsConfig.ExtendNetBirdConfig(peer.ID, peerGroups, nbConfig, extraSettings)

	return &proto.SyncResponse{NetbirdConfig: nbConfig}
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

	network, err := s.accountManager.GetStore().GetAccountNetwork(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		log.WithContext(ctx).Debugf("fast path: lookup account network: %v", err)
		return false, nil
	}

	cached, hit := s.peerSerialCache.Get(peerKey.String())
	if !shouldSkipNetworkMap(peerMeta.GoOS, hit, cached, network.CurrentSerial(), peerMetaHash) {
		return false, nil
	}

	return true, s.runFastPathSync(ctx, reqStart, syncStart, accountID, peerKey, realIP, peerMetaHash, srv, unlock)
}

// runFastPathSync executes the fast path: mark connected, send lean response,
// open the update channel, kick off token refresh, release the per-peer lock,
// then block on handleUpdates until the stream is closed.
func (s *Server) runFastPathSync(
	ctx context.Context,
	reqStart, syncStart time.Time,
	accountID string,
	peerKey wgtypes.Key,
	realIP net.IP,
	peerMetaHash uint64,
	srv proto.ManagementService_SyncServer,
	unlock *func(),
) error {
	if err := s.accountManager.MarkPeerConnected(ctx, peerKey.String(), true, realIP, accountID, syncStart); err != nil {
		log.WithContext(ctx).Warnf("fast path: mark connected for peer %s: %v", peerKey.String(), err)
	}

	peer, err := s.accountManager.GetStore().GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, peerKey.String())
	if err != nil {
		s.syncSem.Add(-1)
		return mapError(ctx, err)
	}

	if err := s.sendFastPathResponse(ctx, peerKey, peer, srv); err != nil {
		log.WithContext(ctx).Debugf("fast path: send response for peer %s: %v", peerKey.String(), err)
		s.syncSem.Add(-1)
		s.cancelPeerRoutinesWithoutLock(ctx, accountID, peer, syncStart)
		return err
	}

	updates, err := s.networkMapController.OnPeerConnected(ctx, accountID, peer.ID)
	if err != nil {
		log.WithContext(ctx).Debugf("fast path: notify peer connected for %s: %v", peerKey.String(), err)
		s.syncSem.Add(-1)
		s.cancelPeerRoutinesWithoutLock(ctx, accountID, peer, syncStart)
		return err
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
	resp := buildFastPathResponse(ctx, s.config, s.secretsManager, s.settingsManager, s.fetchPeerGroups, peer)

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

// fetchPeerGroups is the dependency injected into buildFastPathResponse in
// production. A nil accountManager store is treated as "no groups".
func (s *Server) fetchPeerGroups(ctx context.Context, accountID, peerID string) ([]string, error) {
	return s.accountManager.GetStore().GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
}

// recordPeerSyncEntry writes the serial just delivered to this peer so a
// subsequent reconnect can take the fast path. Called after the slow path's
// sendInitialSync has pushed a full map. A nil cache disables the fast path.
func (s *Server) recordPeerSyncEntry(peerKey string, netMap *nbtypes.NetworkMap, peerMetaHash uint64) {
	if s.peerSerialCache == nil {
		return
	}
	if !s.fastPathFlag.Enabled() {
		return
	}
	if netMap == nil || netMap.Network == nil {
		return
	}
	serial := netMap.Network.CurrentSerial()
	if serial == 0 {
		return
	}
	s.peerSerialCache.Set(peerKey, peerSyncEntry{Serial: serial, MetaHash: peerMetaHash})
}

// recordPeerSyncEntryFromUpdate is the sendUpdate equivalent of
// recordPeerSyncEntry: it extracts the serial from a streamed NetworkMap update
// so the cache stays in sync with what the peer most recently received.
func (s *Server) recordPeerSyncEntryFromUpdate(peerKey string, update *network_map.UpdateMessage, peerMetaHash uint64) {
	if s.peerSerialCache == nil || update == nil || update.Update == nil || update.Update.NetworkMap == nil {
		return
	}
	if !s.fastPathFlag.Enabled() {
		return
	}
	serial := update.Update.NetworkMap.GetSerial()
	if serial == 0 {
		return
	}
	s.peerSerialCache.Set(peerKey, peerSyncEntry{Serial: serial, MetaHash: peerMetaHash})
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
