package server

import (
	"github.com/netbirdio/netbird/management/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"strings"
	"time"
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
}

type PeerStatus struct {
	//LastSeen is the last time peer was connected to the management service
	LastSeen time.Time
	//Connected indicates whether peer is connected to the management service or not
	Connected bool
}

//Peer represents a machine connected to the network.
//The Peer is a Wireguard peer identified by a public key
type Peer struct {
	//Wireguard public key
	Key string
	//A setup key this peer was registered with
	SetupKey string
	//IP address of the Peer
	IP net.IP
	//Meta is a Peer system meta data
	Meta PeerSystemMeta
	//Name is peer's name (machine name)
	Name   string
	Status *PeerStatus
	//The user ID that registered the peer
	UserID string
}

//Copy copies Peer object
func (p *Peer) Copy() *Peer {
	return &Peer{
		Key:      p.Key,
		SetupKey: p.SetupKey,
		IP:       p.IP,
		Meta:     p.Meta,
		Name:     p.Name,
		Status:   p.Status,
	}
}

//GetPeer returns a peer from a Store
func (am *DefaultAccountManager) GetPeer(peerKey string) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	peer, err := am.Store.GetPeer(peerKey)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

//MarkPeerConnected marks peer as connected (true) or disconnected (false)
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

//RenamePeer changes peer's name
func (am *DefaultAccountManager) RenamePeer(accountId string, peerKey string, newName string) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	peer, err := am.Store.GetPeer(peerKey)
	if err != nil {
		return nil, err
	}

	peerCopy := peer.Copy()
	peerCopy.Name = newName
	err = am.Store.SavePeer(accountId, peerCopy)
	if err != nil {
		return nil, err
	}

	return peerCopy, nil
}

//DeletePeer removes peer from the account by it's IP
func (am *DefaultAccountManager) DeletePeer(accountId string, peerKey string) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
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
			}})
	if err != nil {
		return nil, err
	}

	//notify other peers of the change
	peers, err := am.Store.GetAccountPeers(accountId)
	if err != nil {
		return nil, err
	}

	for _, p := range peers {
		peersToSend := []*Peer{}
		for _, remote := range peers {
			if p.Key != remote.Key {
				peersToSend = append(peersToSend, remote)
			}
		}
		update := toRemotePeerConfig(peersToSend)
		err = am.peersUpdateManager.SendUpdate(p.Key,
			&UpdateMessage{
				Update: &proto.SyncResponse{
					// fill those field for backward compatibility
					RemotePeers:        update,
					RemotePeersIsEmpty: len(update) == 0,
					// new field
					NetworkMap: &proto.NetworkMap{
						Serial:             account.Network.CurrentSerial(),
						RemotePeers:        update,
						RemotePeersIsEmpty: len(update) == 0,
					},
				}})
		if err != nil {
			return nil, err
		}
	}

	am.peersUpdateManager.CloseChannel(peerKey)
	return peer, nil
}

//GetPeerByIP returns peer by it's IP
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

	var res []*Peer
	for _, peer := range account.Peers {
		// exclude original peer
		if peer.Key != peerKey {
			res = append(res, peer.Copy())
		}
	}

	return &NetworkMap{
		Peers:   res,
		Network: account.Network.Copy(),
	}, err
}

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key err wit ha code codes.Unauthenticated
// will be returned, meaning the key is invalid
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
// The peer property is just a placeholder for the Peer properties to pass further
func (am *DefaultAccountManager) AddPeer(setupKey string, userId string, peer *Peer) (*Peer, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	upperKey := strings.ToUpper(setupKey)

	var account *Account
	var err error
	var sk *SetupKey
	if len(upperKey) != 0 {
		account, err = am.Store.GetAccountBySetupKey(upperKey)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "unable to register peer, unable to find account with setupKey %s", upperKey)
		}

		sk = getAccountSetupKeyByKey(account, upperKey)
		if sk == nil {
			// shouldn't happen actually
			return nil, status.Errorf(codes.NotFound, "unable to register peer, unknown setupKey %s", upperKey)
		}

		if !sk.IsValid() {
			return nil, status.Errorf(codes.FailedPrecondition, "unable to register peer, setup key was expired or overused %s", upperKey)
		}

	} else if len(userId) != 0 {
		account, err = am.Store.GetUserAccount(userId)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "unable to register peer, unknown user with ID: %s", userId)
		}
	} else {
		// Empty setup key and jwt fail
		return nil, status.Errorf(codes.InvalidArgument, "no setup key or user id provided")
	}

	var takenIps []net.IP
	for _, peer := range account.Peers {
		takenIps = append(takenIps, peer.IP)
	}

	network := account.Network
	nextIp, _ := AllocatePeerIP(network.Net, takenIps)

	newPeer := &Peer{
		Key:      peer.Key,
		SetupKey: upperKey,
		IP:       nextIp,
		Meta:     peer.Meta,
		Name:     peer.Name,
		UserID:   userId,
		Status:   &PeerStatus{Connected: false, LastSeen: time.Now()},
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
