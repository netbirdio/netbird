package mesh

import (
	"github.com/netbirdio/management-integrations/integrations"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/refactor/peers"
	"github.com/netbirdio/netbird/management/refactor/policies"
	"github.com/netbirdio/netbird/management/refactor/settings"
	"github.com/netbirdio/netbird/management/refactor/store"
	"github.com/netbirdio/netbird/management/refactor/users"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
)

type Controller interface {
	LoginPeer()
	SyncPeer()
}

type DefaultController struct {
	store           store.Store
	peersManager    peers.Manager
	userManager     users.Manager
	policiesManager policies.Manager
	settingsManager settings.Manager
}

func NewDefaultController() *DefaultController {
	storeStore, _ := store.NewDefaultStore(store.SqliteStoreEngine, "", nil)
	peersManager := peers.NewDefaultManager(storeStore, nil)
	settingsManager := settings.NewDefaultManager(storeStore)
	usersManager := users.NewDefaultManager(storeStore, peersManager)
	policiesManager := policies.NewDefaultManager(storeStore, peersManager)

	peersManager, settingsManager, usersManager, policiesManager, storeStore = integrations.InjectCloud(peersManager, policiesManager, settingsManager, usersManager, storeStore)

	return &DefaultController{
		store:           storeStore,
		peersManager:    peersManager,
		userManager:     usersManager,
		policiesManager: policiesManager,
		settingsManager: settingsManager,
	}
}

func (c *DefaultController) LoginPeer(login peers.PeerLogin) {

	peer, err := c.peersManager.GetPeerByPubKey(login.WireGuardPubKey)
	if err != nil {
		return nil, nil, status.Errorf(status.Unauthenticated, "peer is not registered")
	}

	if peer.AddedWithSSOLogin() {
		user, err := c.userManager.GetUser(peer.GetUserID())
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

func (c *DefaultController) SyncPeer() {

}

func (c *DefaultController) GetPeerNetworkMap(peerID, dnsDomain string) *NetworkMap {
	peer, err := c.peersManager.GetNetworkPeerByID(peerID)
	if err != nil {
		return &NetworkMap{
			Network: a.Network.Copy(),
		}
	}

	aclPeers, firewallRules := c.policiesManager.GetAccessiblePeersAndFirewallRules(peerID)
	// exclude expired peers
	var peersToConnect []*peers.Peer
	var expiredPeers []*peers.Peer
	accSettings, _ := c.settingsManager.GetSettings(peer.GetAccountID())
	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(accSettings.GetPeerLoginExpiration())
		if accSettings.GetPeerLoginExpirationEnabled() && expired {
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
