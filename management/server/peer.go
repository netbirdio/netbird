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

// GetPeer looks up peer by its public WireGuard key
func (am *DefaultAccountManager) GetPeer(peerPubKey string) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return nil, err
	}

	return account.FindPeerByPubKey(peerPubKey)
}

// GetPeers returns a list of peers under the given account filtering out peers that do not belong to a user if
// the current user is not an admin.
func (am *DefaultAccountManager) GetPeers(accountID, userID string) ([]*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()
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
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return err
	}

	peer, err := account.FindPeerByPubKey(peerPubKey)
	if err != nil {
		return err
	}

	peer.Status.LastSeen = time.Now()
	peer.Status.Connected = connected

	account.UpdatePeer(peer)

	err = am.Store.SaveAccount(account)
	if err != nil {
		return err
	}
	return nil
}

// UpdatePeer updates peer. Only Peer.Name and Peer.SSHEnabled can be updated.
func (am *DefaultAccountManager) UpdatePeer(accountID string, update *Peer) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
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
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
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
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
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
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Invalid peer key %s", peerPubKey)
	}

	aclPeers := am.getPeersByACL(account, peerPubKey)
	routesUpdate := account.GetPeersRoutes(append(aclPeers, account.Peers[peerPubKey]))

	// todo extract this with the store v2
	// this should become part of the method parameters
	// to prevent slow performance when called in a parent loop
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
		DNSUpdate: dnsUpdate,
	}, err
}

// GetPeerNetwork returns the Network for a given peer
func (am *DefaultAccountManager) GetPeerNetwork(peerPubKey string) (*Network, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

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
func (am *DefaultAccountManager) AddPeer(setupKey string, userID string, peer *Peer) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	upperKey := strings.ToUpper(setupKey)

	var account *Account
	var err error
	var sk *SetupKey
	// auto-assign groups that are coming with a SetupKey or a User
	var groupsToAdd []string
	if len(upperKey) != 0 {
		account, err = am.Store.GetAccountBySetupKey(upperKey)
		if err != nil {
			return nil, status.Errorf(
				codes.NotFound,
				"unable to register peer, unable to find account with setupKey %s",
				upperKey,
			)
		}

		sk = getAccountSetupKeyByKey(account, upperKey)
		if sk == nil {
			// shouldn't happen actually
			return nil, status.Errorf(
				codes.NotFound,
				"unable to register peer, unknown setupKey %s",
				upperKey,
			)
		}

		if !sk.IsValid() {
			return nil, status.Errorf(
				codes.FailedPrecondition,
				"unable to register peer, its setup key is invalid (expired, overused or revoked)",
			)
		}

		groupsToAdd = sk.AutoGroups

	} else if len(userID) != 0 {
		account, err = am.Store.GetAccountByUser(userID)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "unable to register peer, unknown user with ID: %s", userID)
		}
		user, ok := account.Users[userID]
		if !ok {
			return nil, status.Errorf(codes.NotFound, "unable to register peer, unknown user with ID: %s", userID)
		}

		groupsToAdd = user.AutoGroups

	} else {
		// Empty setup key and jwt fail
		return nil, status.Errorf(codes.InvalidArgument, "no setup key or user id provided")
	}

	var takenIps []net.IP
	existingLabels := make(lookupMap)
	for _, existingPeer := range account.Peers {
		takenIps = append(takenIps, existingPeer.IP)
		if existingPeer.DNSLabel != "" {
			existingLabels[existingPeer.DNSLabel] = struct{}{}
		}
	}

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

	if len(groupsToAdd) > 0 {
		for _, s := range groupsToAdd {
			if g, ok := account.Groups[s]; ok && g.Name != "All" {
				g.Peers = append(g.Peers, newPeer.Key)
			}
		}
	}

	account.Peers[newPeer.Key] = newPeer
	if len(upperKey) != 0 {
		account.SetupKeys[sk.Key] = sk.IncrementUsage()
	}
	account.Network.IncSerial()

	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding peer")
	}

	return newPeer, nil
}

// UpdatePeerSSHKey updates peer's public SSH key
func (am *DefaultAccountManager) UpdatePeerSSHKey(peerPubKey string, sshKey string) error {
	am.mux.Lock()
	defer am.mux.Unlock()

	if sshKey == "" {
		log.Debugf("empty SSH key provided for peer %s, skipping update", peerPubKey)
		return nil
	}

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
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
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccountByPeerPubKey(peerPubKey)
	if err != nil {
		return err
	}

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
	// notify other peers of the change
	peers := account.GetPeers()
	network := account.Network.Copy()
	var zones []nbdns.CustomZone
	peersCustomZone := getPeersCustomZone(account, am.dnsDomain)
	if peersCustomZone.Domain != "" {
		zones = append(zones, peersCustomZone)
	}

	for _, peer := range peers {
		aclPeers := am.getPeersByACL(account, peer.Key)
		peersUpdate := toRemotePeerConfig(aclPeers)
		routesUpdate := toProtocolRoutes(account.GetPeersRoutes(append(aclPeers, peer)))
		dnsUpdate := toProtocolDNSUpdate(nbdns.Config{
			ServiceEnable:    true,
			CustomZones:      zones,
			NameServerGroups: getPeerNSGroups(account, peer.Key),
		})
		err := am.peersUpdateManager.SendUpdate(peer.Key,
			&UpdateMessage{
				Update: &proto.SyncResponse{
					// fill deprecated fields for backward compatibility
					RemotePeers:        peersUpdate,
					RemotePeersIsEmpty: len(peersUpdate) == 0,
					// new field
					NetworkMap: &proto.NetworkMap{
						Serial:             account.Network.CurrentSerial(),
						RemotePeers:        peersUpdate,
						RemotePeersIsEmpty: len(peersUpdate) == 0,
						PeerConfig:         toPeerConfig(peer, network),
						Routes:             routesUpdate,
						DNSConfig:          dnsUpdate,
					},
				},
			})
		if err != nil {
			return err
		}
	}

	return nil
}
