package mesh

import (
	"github.com/netbirdio/management-integrations/integrations"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/refactor/api/http"
	"github.com/netbirdio/netbird/management/refactor/resources/network"
	networkTypes "github.com/netbirdio/netbird/management/refactor/resources/network/types"
	"github.com/netbirdio/netbird/management/refactor/resources/peers"
	peerTypes "github.com/netbirdio/netbird/management/refactor/resources/peers/types"
	"github.com/netbirdio/netbird/management/refactor/resources/policies"
	"github.com/netbirdio/netbird/management/refactor/resources/routes"
	"github.com/netbirdio/netbird/management/refactor/resources/settings"
	"github.com/netbirdio/netbird/management/refactor/resources/users"
	"github.com/netbirdio/netbird/management/refactor/store"
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
	networkManager  network.Manager
	routesManager   routes.Manager
}

func NewDefaultController() *DefaultController {
	storeStore, _ := store.NewDefaultStore(store.SqliteStoreEngine, "", nil)
	settingsManager := settings.NewDefaultManager(storeStore)
	networkManager := network.NewDefaultManager()
	peersManager := peers.NewDefaultManager(storeStore, settingsManager)
	routesManager := routes.NewDefaultManager(storeStore, peersManager)
	usersManager := users.NewDefaultManager(storeStore, peersManager)
	policiesManager := policies.NewDefaultManager(storeStore, peersManager)

	apiHandler, _ := http.NewDefaultAPIHandler()

	peersManager, settingsManager, usersManager, policiesManager, storeStore, apiHandler = integrations.InjectCloud(peersManager, policiesManager, settingsManager, usersManager, storeStore)

	return &DefaultController{
		store:           storeStore,
		peersManager:    peersManager,
		userManager:     usersManager,
		policiesManager: policiesManager,
		settingsManager: settingsManager,
		networkManager:  networkManager,
		routesManager:   routesManager,
	}
}

func (c *DefaultController) LoginPeer(login peerTypes.PeerLogin) (*peerTypes.Peer, *networkTypes.NetworkMap, error) {

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

	settings, err := c.settingsManager.GetSettings(peer.GetAccountID())
	if err != nil {
		return nil, nil, err
	}

	// this flag prevents unnecessary calls to the persistent store.
	shouldStorePeer := false
	updateRemotePeers := false
	if peerLoginExpired(peer, settings) {
		err = checkAuth(login.UserID, peer)
		if err != nil {
			return nil, nil, err
		}
		// If peer was expired before and if it reached this point, it is re-authenticated.
		// UserID is present, meaning that JWT validation passed successfully in the API layer.
		peer.UpdateLastLogin()
		updateRemotePeers = true
		shouldStorePeer = true

		pm.eventsManager.StoreEvent(login.UserID, peer.GetID(), peer.GetAccountID(), activity.UserLoggedInPeer, peer.EventMeta(pm.accountManager.GetDNSDomain()))
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

func (c *DefaultController) GetPeerNetworkMap(accountID, peerID, dnsDomain string) (*networkTypes.NetworkMap, error) {
	unlock := c.store.AcquireAccountLock(accountID)
	defer unlock()

	network, err := c.networkManager.GetNetwork(accountID)
	if err != nil {
		return nil, err
	}

	peer, err := c.peersManager.GetNetworkPeerByID(peerID)
	if err != nil {
		return &networkTypes.NetworkMap{
			Network: network.Copy(),
		}, nil
	}

	aclPeers, firewallRules := c.policiesManager.GetAccessiblePeersAndFirewallRules(peerID)
	// exclude expired peers
	var peersToConnect []*peerTypes.Peer
	var expiredPeers []*peerTypes.Peer
	accSettings, _ := c.settingsManager.GetSettings(peer.GetAccountID())
	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(accSettings.GetPeerLoginExpiration())
		if accSettings.GetPeerLoginExpirationEnabled() && expired {
			expiredPeers = append(expiredPeers, &p)
			continue
		}
		peersToConnect = append(peersToConnect, &p)
	}

	routesUpdate := c.routesManager.GetRoutesToSync(peerID, peersToConnect, accountID)

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

	return &networkTypes.NetworkMap{
		Peers:         peersToConnect,
		Network:       network.Copy(),
		Routes:        routesUpdate,
		DNSConfig:     dnsUpdate,
		OfflinePeers:  expiredPeers,
		FirewallRules: firewallRules,
	}, nil
}
