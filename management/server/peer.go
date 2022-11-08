package server

import (
	nbdns "github.com/netbirdio/netbird/dns"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PeerSystemMeta is a metadata of a Peer machine system
type PeerSystemMeta struct {
	Hostname  string
	GoOS      string
	Kernel    string
	Core      string
	Platform  string
	OS        string
	WtVersion string
	UIVersion string
}

type PeerStatus struct {
	// LastSeen is the last time peer was connected to the management service
	LastSeen time.Time
	// Connected indicates whether peer is connected to the management service or not
	Connected bool
}

// Peer represents a machine connected to the network.
// The Peer is a Wireguard peer identified by a public key
type Peer struct {
	// Wireguard public key
	Key string
	// A setup key this peer was registered with
	SetupKey string
	// IP address of the Peer
	IP net.IP
	// Meta is a Peer system meta data
	Meta PeerSystemMeta
	// Name is peer's name (machine name)
	Name string
	// DNSLabel is the parsed peer name for domain resolution. It is used to form an FQDN by appending the account's
	// domain to the peer label. e.g. peer-dns-label.netbird.cloud
	DNSLabel string
	// Status peer's management connection status
	Status *PeerStatus
	// The user ID that registered the peer
	UserID string
	// SSHKey is a public SSH key of the peer
	SSHKey string
	// SSHEnabled indicated whether SSH server is enabled on the peer
	SSHEnabled bool
}

// Copy copies Peer object
func (p *Peer) Copy() *Peer {
	return &Peer{
		Key:        p.Key,
		SetupKey:   p.SetupKey,
		IP:         p.IP,
		Meta:       p.Meta,
		Name:       p.Name,
		Status:     p.Status,
		UserID:     p.UserID,
		SSHKey:     p.SSHKey,
		SSHEnabled: p.SSHEnabled,
		DNSLabel:   p.DNSLabel,
	}
}

// Copy PeerStatus
func (p *PeerStatus) Copy() *PeerStatus {
	return &PeerStatus{
		LastSeen:  p.LastSeen,
		Connected: p.Connected,
	}
}

// GetPeer looks up peer by its public WireGuard key
func (am *DefaultAccountManager) GetPeer(peerPubKey string) (*Peer, error) {

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return nil, err
	}

	return account.FindPeerByPubKey(peerPubKey)
}

// GetPeers returns a list of peers under the given account filtering out peers that do not belong to a user if
// the current user is not an admin.
func (am *DefaultAccountManager) GetPeers(accountID, userID string) ([]*Peer, error) {

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	peers := make([]*Peer, 0, len(account.Peers))
	for _, peer := range account.Peers {
		if !user.IsAdmin() && user.Id != peer.UserID {
			// only display peers that belong to the current user if the current user is not an admin
			continue
		}
		peers = append(peers, peer.Copy())
	}

	return peers, nil
}

// MarkPeerConnected marks peer as connected (true) or disconnected (false)
func (am *DefaultAccountManager) MarkPeerConnected(peerPubKey string, connected bool) error {

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return err
	}

	peer, err := account.FindPeerByPubKey(peerPubKey)
	if err != nil {
		return err
	}

	newStatus := peer.Status.Copy()
	newStatus.LastSeen = time.Now()
	newStatus.Connected = connected
	peer.Status = newStatus
	account.UpdatePeer(peer)

	err = am.Store.SavePeerStatus(account.Id, peerPubKey, *newStatus)
	if err != nil {
		return err
	}
	return nil
}

// UpdatePeer updates peer. Only Peer.Name and Peer.SSHEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(accountID string, update *Peer) (*Peer, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	//TODO Peer.ID migration: we will need to replace search by ID here
	peer, err := account.FindPeerByPubKey(update.Key)
	if err != nil {
		return nil, err
	}

	if peer.Name != "" {
		peer.Name = update.Name
	}
	peer.SSHEnabled = update.SSHEnabled

	existingLabels := account.getPeerDNSLabels()

	newLabel, err := getPeerHostLabel(peer.Name, existingLabels)
	if err != nil {
		return nil, err
	}

	peer.DNSLabel = newLabel

	account.UpdatePeer(peer)

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

// DeletePeer removes peer from the account by its IP
func (am *DefaultAccountManager) DeletePeer(accountID string, peerPubKey string) (*Peer, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	peer, err := account.FindPeerByPubKey(peerPubKey)
	if err != nil {
		return nil, err
	}

	account.DeletePeer(peerPubKey)

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	err = am.peersUpdateManager.SendUpdate(peerPubKey,
		&UpdateMessage{
			Update: &proto.SyncResponse{
				// fill those field for backward compatibility
				RemotePeers:        []*proto.RemotePeerConfig{},
				RemotePeersIsEmpty: true,
				// new field
				NetworkMap: &proto.NetworkMap{
					Serial:             account.Network.CurrentSerial(),
					RemotePeers:        []*proto.RemotePeerConfig{},
					RemotePeersIsEmpty: true,
				},
			},
		})
	if err != nil {
		return nil, err
	}

	// TODO Peer.ID migration: we will need to replace search by Peer.ID here
	if err := am.updateAccountPeers(account); err != nil {
		return nil, err
	}

	am.peersUpdateManager.CloseChannel(peerPubKey)
	return peer, nil
}

// GetPeerByIP returns peer by its IP
func (am *DefaultAccountManager) GetPeerByIP(accountID string, peerIP string) (*Peer, error) {

	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	for _, peer := range account.Peers {
		if peerIP == peer.IP.String() {
			return peer, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "peer with IP %s not found", peerIP)
}

// GetNetworkMap returns Network map for a given peer (omits original peer from the Peers result)
func (am *DefaultAccountManager) GetNetworkMap(peerPubKey string) (*NetworkMap, error) {

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Invalid peer key %s", peerPubKey)
	}

	aclPeers := am.getPeersByACL(account, peerPubKey)
	routesUpdate := account.GetPeersRoutes(append(aclPeers, account.Peers[peerPubKey]))

	var zones []nbdns.CustomZone
	peersCustomZone := getPeersCustomZone(account, am.dnsDomain)
	if peersCustomZone.Domain != "" {
		zones = append(zones, peersCustomZone)
	}

	dnsUpdate := nbdns.Config{
		ServiceEnable:    true,
		CustomZones:      zones,
		NameServerGroups: getPeerNSGroups(account, peerPubKey),
	}

	return &NetworkMap{
		Peers:     aclPeers,
		Network:   account.Network.Copy(),
		Routes:    routesUpdate,
		DNSConfig: dnsUpdate,
	}, err
}

// GetPeerNetwork returns the Network for a given peer
func (am *DefaultAccountManager) GetPeerNetwork(peerPubKey string) (*Network, error) {

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid peer key %s", peerPubKey)
	}

	return account.Network.Copy(), err
}

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key err wit ha code codes.Unauthenticated
// will be returned, meaning the key is invalid
// If a User ID is provided, it means that we passed the authentication using JWT, then we look for account by User ID and register the peer
// to it. We also add the User ID to the peer metadata to identify registrant.
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
// The peer property is just a placeholder for the Peer properties to pass further
func (am *DefaultAccountManager) AddPeer(setupKey, userID string, peer *Peer) (*Peer, error) {

	upperKey := strings.ToUpper(setupKey)
	var account *Account
	var err error
	addedByUser := false
	if len(userID) > 0 {
		addedByUser = true
		account, err = am.Store.GetAccountByUser(userID)
	} else {
		account, err = am.Store.GetAccountBySetupKey(setupKey)
	}
	if err != nil {
		return nil, Errorf(AccountNotFound, "failed adding new peer: account not found")
	}

	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return nil, err
	}

	if !addedByUser {
		// validate the setup key if adding with a key
		sk, err := account.FindSetupKey(upperKey)
		if err != nil {
			return nil, err
		}

		if !sk.IsValid() {
			return nil, Errorf(PreconditionFailed, "couldn't add peer: setup key is invalid")
		}

		account.SetupKeys[sk.Key] = sk.IncrementUsage()
	}

	takenIps := account.getTakenIPs()
	existingLabels := account.getPeerDNSLabels()

	newLabel, err := getPeerHostLabel(peer.Name, existingLabels)
	if err != nil {
		return nil, err
	}

	peer.DNSLabel = newLabel
	network := account.Network
	nextIp, err := AllocatePeerIP(network.Net, takenIps)
	if err != nil {
		return nil, err
	}

	newPeer := &Peer{
		Key:        peer.Key,
		SetupKey:   upperKey,
		IP:         nextIp,
		Meta:       peer.Meta,
		Name:       peer.Name,
		DNSLabel:   newLabel,
		UserID:     userID,
		Status:     &PeerStatus{Connected: false, LastSeen: time.Now()},
		SSHEnabled: false,
		SSHKey:     peer.SSHKey,
	}

	// add peer to 'All' group
	group, err := account.GetGroupAll()
	if err != nil {
		return nil, err
	}
	group.Peers = append(group.Peers, newPeer.Key)

	var groupsToAdd []string
	if addedByUser {
		groupsToAdd, err = account.getUserGroups(userID)
		if err != nil {
			return nil, err
		}
	} else {
		groupsToAdd, err = account.getSetupKeyGroups(upperKey)
		if err != nil {
			return nil, err
		}
	}

	if len(groupsToAdd) > 0 {
		for _, s := range groupsToAdd {
			if g, ok := account.Groups[s]; ok && g.Name != "All" {
				g.Peers = append(g.Peers, newPeer.Key)
			}
		}
	}

	account.Peers[newPeer.Key] = newPeer
	account.Network.IncSerial()
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding peer")
	}

	return newPeer, nil
}

// UpdatePeerSSHKey updates peer's public SSH key
func (am *DefaultAccountManager) UpdatePeerSSHKey(peerPubKey string, sshKey string) error {

	if sshKey == "" {
		log.Debugf("empty SSH key provided for peer %s, skipping update", peerPubKey)
		return nil
	}

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	// ensure that we consider modification happened meanwhile (because we were outside the account lock when we fetched the account)
	account, err = am.Store.GetAccount(account.Id)
	if err != nil {
		return err
	}

	peer, err := account.FindPeerByPubKey(peerPubKey)
	if err != nil {
		return err
	}

	if peer.SSHKey == sshKey {
		log.Debugf("same SSH key provided for peer %s, skipping update", peerPubKey)
		return nil
	}

	peer.SSHKey = sshKey
	account.UpdatePeer(peer)

	err = am.Store.SaveAccount(account)
	if err != nil {
		return err
	}

	// trigger network map update
	return am.updateAccountPeers(account)
}

// UpdatePeerMeta updates peer's system metadata
func (am *DefaultAccountManager) UpdatePeerMeta(peerPubKey string, meta PeerSystemMeta) error {

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return err
	}

	unlock := am.Store.AcquireAccountLock(account.Id)
	defer unlock()

	peer, err := account.FindPeerByPubKey(peerPubKey)
	if err != nil {
		return err
	}

	// Avoid overwriting UIVersion if the update was triggered sole by the CLI client
	if meta.UIVersion == "" {
		meta.UIVersion = peer.Meta.UIVersion
	}

	peer.Meta = meta
	account.UpdatePeer(peer)

	err = am.Store.SaveAccount(account)
	if err != nil {
		return err
	}
	return nil
}

// getPeersByACL returns all peers that given peer has access to.
func (am *DefaultAccountManager) getPeersByACL(account *Account, peerPubKey string) []*Peer {
	var peers []*Peer
	srcRules, dstRules := account.GetPeerRules(peerPubKey)

	groups := map[string]*Group{}
	for _, r := range srcRules {
		if r.Disabled {
			continue
		}
		if r.Flow == TrafficFlowBidirect {
			for _, gid := range r.Destination {
				if group, ok := account.Groups[gid]; ok {
					groups[gid] = group
				}
			}
		}
	}

	for _, r := range dstRules {
		if r.Disabled {
			continue
		}
		if r.Flow == TrafficFlowBidirect {
			for _, gid := range r.Source {
				if group, ok := account.Groups[gid]; ok {
					groups[gid] = group
				}
			}
		}
	}

	peersSet := make(map[string]struct{})
	for _, g := range groups {
		for _, pid := range g.Peers {
			peer, ok := account.Peers[pid]
			if !ok {
				log.Warnf(
					"peer %s found in group %s but doesn't belong to account %s",
					pid,
					g.ID,
					account.Id,
				)
				continue
			}
			// exclude original peer
			if _, ok := peersSet[peer.Key]; peer.Key != peerPubKey && !ok {
				peersSet[peer.Key] = struct{}{}
				peers = append(peers, peer.Copy())
			}
		}
	}

	return peers
}

// updateAccountPeers updates all peers that belong to an account.
// Should be called when changes have to be synced to peers.
func (am *DefaultAccountManager) updateAccountPeers(account *Account) error {
	peers := account.GetPeers()

	for _, peer := range peers {
		remotePeerNetworkMap, err := am.GetNetworkMap(peer.Key)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to fetch network map for peer %s, error: %v", peer.Key, err)
		}

		update := toSyncResponse(nil, peer, nil, remotePeerNetworkMap)
		err = am.peersUpdateManager.SendUpdate(peer.Key, &UpdateMessage{Update: update})
		if err != nil {
			return status.Errorf(codes.Internal, "unable to send update for peer %s, error: %v", peer.Key, err)
		}
	}

	return nil
}
