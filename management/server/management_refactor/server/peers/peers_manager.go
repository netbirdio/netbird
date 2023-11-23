package peers

import (
	"time"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/management_refactor/server/accounts"
	"github.com/netbirdio/netbird/management/server/management_refactor/server/events"
	"github.com/netbirdio/netbird/management/server/management_refactor/server/users"
	"github.com/netbirdio/netbird/management/server/status"
)

// PeerLogin used as a data object between the gRPC API and AccountManager on Login request.
type PeerLogin struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
	// SSHKey is a peer's ssh key. Can be empty (e.g., old version do not provide it, or this feature is disabled)
	SSHKey string
	// Meta is the system information passed by peer, must be always present.
	Meta PeerSystemMeta
	// UserID indicates that JWT was used to log in, and it was valid. Can be empty when SetupKey is used or auth is not required.
	UserID string
	// AccountID indicates that JWT was used to log in, and it was valid. Can be empty when SetupKey is used or auth is not required.
	AccountID string
	// SetupKey references to a server.SetupKey to log in. Can be empty when UserID is used or auth is not required.
	SetupKey string
}

type PeerStatus struct {
	// LastSeen is the last time peer was connected to the management service
	LastSeen time.Time
	// Connected indicates whether peer is connected to the management service or not
	Connected bool
	// LoginExpired
	LoginExpired bool
}

// PeerSync used as a data object between the gRPC API and AccountManager on Sync request.
type PeerSync struct {
	// WireGuardPubKey is a peers WireGuard public key
	WireGuardPubKey string
}

type PeersManager interface {
	LoginPeer(login PeerLogin) (*Peer, *accounts.NetworkMap, error)
}

type DefaultPeersManager struct {
	repository     PeerRepository
	userManager    users.UserManager
	accountManager accounts.AccountManager
	eventsManager  events.EventsManager
}

// LoginPeer logs in or registers a peer.
// If peer doesn't exist the function checks whether a setup key or a user is present and registers a new peer if so.
func (pm *DefaultPeersManager) LoginPeer(login PeerLogin) (*Peer, *accounts.NetworkMap, error) {

	peer, err := pm.repository.findPeerByPubKey(login.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.Errorf(status.Unauthenticated, "peer is not registered")
	}

	if peer.AddedWithSSOLogin() {
		user, err := pm.userManager.GetUser(peer.UserID)
		if err != nil {
			return nil, nil, err
		}
		if user.IsBlocked() {
			return nil, nil, status.Errorf(status.PermissionDenied, "user is blocked")
		}
	}

	account, err := pm.accountManager.GetAccount(peer.AccountID)
	if err != nil {
		return nil, nil, err
	}

	// this flag prevents unnecessary calls to the persistent store.
	shouldStorePeer := false
	updateRemotePeers := false
	if peerLoginExpired(peer, account) {
		err = checkAuth(login.UserID, peer)
		if err != nil {
			return nil, nil, err
		}
		// If peer was expired before and if it reached this point, it is re-authenticated.
		// UserID is present, meaning that JWT validation passed successfully in the API layer.
		peer.UpdateLastLogin()
		updateRemotePeers = true
		shouldStorePeer = true

		pm.eventsManager.StoreEvent(login.UserID, peer.ID, account.Id, activity.UserLoggedInPeer, peer.EventMeta(pm.accountManager.GetDNSDomain()))
	}

	if peer.UpdateMetaIfNew(login.Meta) {
		shouldStorePeer = true
	}

	if peer.CheckAndUpdatePeerSSHKey(login.SSHKey) {
		shouldStorePeer = true
	}

	if shouldStorePeer {
		err := pm.repository.updatePeer(peer)
		if err != nil {
			return nil, nil, err
		}
	}

	if updateRemotePeers {
		am.updateAccountPeers(account)
	}
	return peer, account.GetPeerNetworkMap(peer.ID, pm.accountManager.GetDNSDomain()), nil
}

// SyncPeer checks whether peer is eligible for receiving NetworkMap (authenticated) and returns its NetworkMap if eligible
func (pm *DefaultPeersManager) SyncPeer(sync PeerSync) (*Peer, *accounts.NetworkMap, error) {
	// we found the peer, and we follow a normal login flow
	// unlock := am.Store.AcquireAccountLock(account.Id)
	// defer unlock()

	peer, err := pm.repository.findPeerByPubKey(sync.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.Errorf(status.Unauthenticated, "peer is not registered")
	}

	if peer.AddedWithSSOLogin() {
		user, err := pm.userManager.GetUser(peer.UserID)
		if err != nil {
			return nil, nil, err
		}
		if user.IsBlocked() {
			return nil, nil, status.Errorf(status.PermissionDenied, "user is blocked")
		}
	}

	account, err := pm.accountManager.GetAccount(peer.AccountID)
	if err != nil {
		return nil, nil, err
	}

	if peerLoginExpired(peer, account) {
		return nil, nil, status.Errorf(status.PermissionDenied, "peer login has expired, please log in once more")
	}

	return &peer, account.GetPeerNetworkMap(peer.ID, pm.accountManager.GetDNSDomain()), nil
}

func (pm *DefaultPeersManager) GetNetworkMap(peerID string, dnsDomain string) (*accounts.NetworkMap, error) {
	aclPeers, firewallRules := a.getPeerConnectionResources(peerID)
	// exclude expired peers
	var peersToConnect []*Peer
	var expiredPeers []*Peer
	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(a.Settings.PeerLoginExpiration)
		if a.Settings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, p)
			continue
		}
		peersToConnect = append(peersToConnect, p)
	}

	routesUpdate := a.getRoutesToSync(peerID, peersToConnect)

	dnsManagementStatus := a.getPeerDNSManagementStatus(peerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var zones []nbdns.CustomZone
		peersCustomZone := getPeersCustomZone(a, dnsDomain)
		if peersCustomZone.Domain != "" {
			zones = append(zones, peersCustomZone)
		}
		dnsUpdate.CustomZones = zones
		dnsUpdate.NameServerGroups = getPeerNSGroups(a, peerID)
	}

	return &NetworkMap{
		Peers:         peersToConnect,
		Network:       a.Network.Copy(),
		Routes:        routesUpdate,
		DNSConfig:     dnsUpdate,
		OfflinePeers:  expiredPeers,
		FirewallRules: firewallRules,
	}
}

func peerLoginExpired(peer Peer, account accounts.Account) bool {
	expired, expiresIn := peer.LoginExpired(account.Settings.PeerLoginExpiration)
	expired = account.Settings.PeerLoginExpirationEnabled && expired
	if expired || peer.Status.LoginExpired {
		log.Debugf("peer's %s login expired %v ago", peer.ID, expiresIn)
		return true
	}
	return false
}

func checkAuth(loginUserID string, peer Peer) error {
	if loginUserID == "" {
		// absence of a user ID indicates that JWT wasn't provided.
		return status.Errorf(status.PermissionDenied, "peer login has expired, please log in once more")
	}
	if peer.UserID != loginUserID {
		log.Warnf("user mismatch when logging in peer %s: peer user %s, login user %s ", peer.ID, peer.UserID, loginUserID)
		return status.Errorf(status.Unauthenticated, "can't login")
	}
	return nil
}
