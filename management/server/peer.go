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
	// DNSLabel is the peer's dns label, used to form a fqdn with the DNS peer domain
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

// GetPeer returns a peer from a Store
func (am *DefaultAccountManager) GetPeer(peerKey string) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	peer, err := am.Store.GetPeer(peerKey)
	if err != nil {
		return nil, err
	}

	return peer, nil
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
func (am *DefaultAccountManager) MarkPeerConnected(peerKey string, connected bool) error {
	am.mux.Lock()
	defer am.mux.Unlock()

	peer, err := am.Store.GetPeer(peerKey)
	if err != nil {
		return err
	}

	account, err := am.Store.GetPeerAccount(peerKey)
	if err != nil {
		return err
	}

	peerCopy := peer.Copy()
	peerCopy.Status.LastSeen = time.Now()
	peerCopy.Status.Connected = connected
	err = am.Store.SavePeer(account.Id, peerCopy)
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

	peer, err := am.Store.GetPeer(update.Key)
	if err != nil {
		return nil, err
	}

	peerCopy := peer.Copy()
	if peer.Name != "" {
		peerCopy.Name = update.Name
	}

	existingLabels := account.getPeerDNSLabels()

	newLabel, err := getPeerHostLabel(peerCopy.Name, existingLabels)
	if err != nil {
		return nil, err
	}

	peerCopy.DNSLabel = newLabel

	peerCopy.SSHEnabled = update.SSHEnabled

	err = am.Store.SavePeer(accountID, peerCopy)
	if err != nil {
		return nil, err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		return nil, err
	}

	return peerCopy, nil

}

// RenamePeer changes peer's name
func (am *DefaultAccountManager) RenamePeer(
	accountId string,
	peerKey string,
	newName string,
) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	peer, err := am.Store.GetPeer(peerKey)
	if err != nil {
		return nil, err
	}

	peerCopy := peer.Copy()
	peerCopy.Name = newName

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	existingLabels := account.getPeerDNSLabels()

	newLabel, err := getPeerHostLabel(peerCopy.Name, existingLabels)
	if err != nil {
		return nil, err
	}

	peerCopy.DNSLabel = newLabel

	err = am.Store.SavePeer(accountId, peerCopy)
	if err != nil {
		return nil, err
	}

	return peerCopy, nil
}

// DeletePeer removes peer from the account by it's IP
func (am *DefaultAccountManager) DeletePeer(accountId string, peerKey string) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	// delete peer from groups
	for _, g := range account.Groups {
		for i, pk := range g.Peers {
			if pk == peerKey {
				g.Peers = append(g.Peers[:i], g.Peers[i+1:]...)
				break
			}
		}
	}

	peer, err := am.Store.DeletePeer(accountId, peerKey)
	if err != nil {
		return nil, err
	}

	account.Network.IncSerial()
	err = am.Store.SaveAccount(account)
	if err != nil {
		return nil, err
	}

	err = am.peersUpdateManager.SendUpdate(peerKey,
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

	if err := am.updateAccountPeers(account); err != nil {
		return nil, err
	}

	am.peersUpdateManager.CloseChannel(peerKey)
	return peer, nil
}

// GetPeerByIP returns peer by it's IP
func (am *DefaultAccountManager) GetPeerByIP(accountId string, peerIP string) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountId)
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
func (am *DefaultAccountManager) GetNetworkMap(peerKey string) (*NetworkMap, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetPeerAccount(peerKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Invalid peer key %s", peerKey)
	}

	aclPeers := am.getPeersByACL(account, peerKey)
	routesUpdate := am.getPeersRoutes(append(aclPeers, account.Peers[peerKey]))

	return &NetworkMap{
		Peers:   aclPeers,
		Network: account.Network.Copy(),
		Routes:  routesUpdate,
	}, err
}

// GetPeerNetwork returns the Network for a given peer
func (am *DefaultAccountManager) GetPeerNetwork(peerKey string) (*Network, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetPeerAccount(peerKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Invalid peer key %s", peerKey)
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
func (am *DefaultAccountManager) AddPeer(
	setupKey string,
	userID string,
	peer *Peer,
) (*Peer, error) {
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
		account, err = am.Store.GetUserAccount(userID)
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
	// todo finish
	var existingLabels := make(lookupMap)
	for _, peer := range account.Peers {
		takenIps = append(takenIps, peer.IP)
	}

	existingLabels := account.getPeerDNSLabels()

	newLabel, err := getPeerHostLabel(peerCopy.Name, existingLabels)
	if err != nil {
		return nil, err
	}

	peerCopy.DNSLabel = newLabel

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
func (am *DefaultAccountManager) UpdatePeerSSHKey(peerKey string, sshKey string) error {
	am.mux.Lock()
	defer am.mux.Unlock()

	if sshKey == "" {
		log.Debugf("empty SSH key provided for peer %s, skipping update", peerKey)
		return nil
	}

	peer, err := am.Store.GetPeer(peerKey)
	if err != nil {
		return err
	}

	if peer.SSHKey == sshKey {
		log.Debugf("same SSH key provided for peer %s, skipping update", peerKey)
		return nil
	}

	account, err := am.Store.GetPeerAccount(peerKey)
	if err != nil {
		return err
	}

	peerCopy := peer.Copy()
	peerCopy.SSHKey = sshKey

	err = am.Store.SavePeer(account.Id, peerCopy)
	if err != nil {
		return err
	}

	// trigger network map update
	return am.updateAccountPeers(account)
}

// UpdatePeerMeta updates peer's system metadata
func (am *DefaultAccountManager) UpdatePeerMeta(peerKey string, meta PeerSystemMeta) error {
	am.mux.Lock()
	defer am.mux.Unlock()

	peer, err := am.Store.GetPeer(peerKey)
	if err != nil {
		return err
	}

	account, err := am.Store.GetPeerAccount(peerKey)
	if err != nil {
		return err
	}

	peerCopy := peer.Copy()
	// Avoid overwriting UIVersion if the update was triggered sole by the CLI client
	if meta.UIVersion == "" {
		meta.UIVersion = peerCopy.Meta.UIVersion
	}

	peerCopy.Meta = meta

	err = am.Store.SavePeer(account.Id, peerCopy)
	if err != nil {
		return err
	}
	return nil
}

// getPeersByACL returns all peers that given peer has access to.
func (am *DefaultAccountManager) getPeersByACL(account *Account, peerKey string) []*Peer {
	var peers []*Peer
	srcRules, err := am.Store.GetPeerSrcRules(account.Id, peerKey)
	if err != nil {
		srcRules = []*Rule{}
	}

	dstRules, err := am.Store.GetPeerDstRules(account.Id, peerKey)
	if err != nil {
		dstRules = []*Rule{}
	}

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
			if _, ok := peersSet[peer.Key]; peer.Key != peerKey && !ok {
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
	peers, err := am.Store.GetAccountPeers(account.Id)
	if err != nil {
		return err
	}

	network := account.Network.Copy()
	var zones []nbdns.CustomZone
	peersCustomZone := getPeersCustomZone(account, am.dnsDomain)
	if peersCustomZone.Domain != "" {
		zones = append(zones, peersCustomZone)
	}

	for _, peer := range peers {
		aclPeers := am.getPeersByACL(account, peer.Key)
		peersUpdate := toRemotePeerConfig(aclPeers)
		routesUpdate := toProtocolRoutes(am.getPeersRoutes(append(aclPeers, peer)))
		dnsUpdate := toProtocolDNSUpdate(zones, getPeerNSGroups(account, peer.Key))
		err = am.peersUpdateManager.SendUpdate(peer.Key,
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
						DNSUpdate:          dnsUpdate,
					},
				},
			})
		if err != nil {
			return err
		}
	}

	return nil
}
