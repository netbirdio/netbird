package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"strings"
	"time"
)

//Peer represents a machine connected to the network.
//The Peer is a Wireguard peer identified by a public key
type Peer struct {
	//Wireguard public key
	Key string
	//A setup key this peer was registered with
	SetupKey string
	//IP address of the Peer
	IP net.IP
	//OS is peer's operating system
	OS string
	//Name is peer's name (machine name)
	Name string
	//LastSeen is the last time peer was connected to the management service
	LastSeen time.Time
	//Connected indicates whether peer is connected to the management service or not
	Connected bool
}

//Copy copies Peer object
func (p *Peer) Copy() *Peer {
	return &Peer{
		Key:       p.Key,
		SetupKey:  p.SetupKey,
		IP:        p.IP,
		OS:        p.OS,
		Name:      p.Name,
		LastSeen:  p.LastSeen,
		Connected: p.Connected,
	}
}

//GetPeer returns a peer from a Store
func (manager *AccountManager) GetPeer(peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	peer, err := manager.Store.GetPeer(peerKey)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

//RenamePeer changes peer's name
func (manager *AccountManager) RenamePeer(accountId string, peerKey string, newName string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	peer, err := manager.Store.GetPeer(peerKey)
	if err != nil {
		return nil, err
	}

	peerCopy := peer.Copy()
	peerCopy.Name = newName
	err = manager.Store.SavePeer(accountId, peerCopy)
	if err != nil {
		return nil, err
	}

	return peerCopy, nil
}

//DeletePeer removes peer from the account by it's IP
func (manager *AccountManager) DeletePeer(accountId string, peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()
	return manager.Store.DeletePeer(accountId, peerKey)
}

//GetPeerByIP returns peer by it's IP
func (manager *AccountManager) GetPeerByIP(accountId string, peerIP string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, err := manager.Store.GetAccount(accountId)
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

// GetPeersForAPeer returns a list of peers available for a given peer (key)
// Effectively all the peers of the original peer's account except for the peer itself
func (manager *AccountManager) GetPeersForAPeer(peerKey string) ([]*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, err := manager.Store.GetPeerAccount(peerKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Invalid peer key %s", peerKey)
	}

	var res []*Peer
	for _, peer := range account.Peers {
		if peer.Key != peerKey {
			res = append(res, peer)
		}
	}

	return res, nil
}

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key err wit ha code codes.Unauthenticated
// will be returned, meaning the key is invalid
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
// If the specified setupKey is empty then a new Account will be created //todo remove this part
func (manager *AccountManager) AddPeer(setupKey string, peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	upperKey := strings.ToUpper(setupKey)

	var account *Account
	var err error
	var sk *SetupKey
	if len(upperKey) == 0 {
		// Empty setup key, create a new account for it.
		account, sk = newAccount()
	} else {
		account, err = manager.Store.GetAccountBySetupKey(upperKey)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "unknown setupKey %s", upperKey)
		}

		sk = getAccountSetupKeyByKey(account, upperKey)
		if sk == nil {
			// shouldn't happen actually
			return nil, status.Errorf(codes.NotFound, "unknown setupKey %s", upperKey)
		}
	}

	if !sk.IsValid() {
		return nil, status.Errorf(codes.FailedPrecondition, "setup key was expired or overused %s", upperKey)
	}

	var takenIps []net.IP
	for _, peer := range account.Peers {
		takenIps = append(takenIps, peer.IP)
	}

	network := account.Network
	nextIp, _ := AllocatePeerIP(network.Net, takenIps)

	newPeer := &Peer{
		Key:       peerKey,
		SetupKey:  sk.Key,
		IP:        nextIp,
		OS:        "todo",
		Name:      "todo",
		LastSeen:  time.Now(),
		Connected: true,
	}

	account.Peers[newPeer.Key] = newPeer
	account.SetupKeys[sk.Key] = sk.IncrementUsage()
	err = manager.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding peer")
	}

	return newPeer, nil

}
