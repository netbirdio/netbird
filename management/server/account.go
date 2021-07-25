package server

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"
)

type AccountManager struct {
	Store Store
	// mutex to synchronise account operations (e.g. generating Peer IP address inside the Network)
	mux sync.Mutex
}

// Account represents a unique account of the system
type Account struct {
	Id        string
	SetupKeys map[string]*SetupKey
	Network   *Network
}

// SetupKey represents a pre-authorized key used to register machines (peers)
// One key might have multiple machines
type SetupKey struct {
	Key string
}

// Peer represents a machine connected to the network.
// The Peer is a Wireguard peer identified by a public key
type Peer struct {
	AccountId string
	// Wireguard public key
	Key string
	// A setup key this peer was registered with
	SetupKey *SetupKey

	// IP address of the Peer
	Addr string
}

// NewManager creates a new AccountManager with a provided Store
func NewManager(store Store) *AccountManager {
	return &AccountManager{
		Store: store,
		mux:   sync.Mutex{},
	}
}

// GetPeer returns a peer from a Store
func (manager *AccountManager) GetPeer(peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	peer, err := manager.Store.GetPeer(peerKey)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "provided peer key doesn't exists %s", peerKey)
	}

	return peer, nil
}

// GetPeersForAPeer returns a list of peers available for a given peer (key)
// Effectively all the peers of the original peer's account if any
func (manager *AccountManager) GetPeersForAPeer(peerKey string) ([]*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, err := manager.Store.GetPeerAccount(peerKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Invalid peer key %s", peerKey)
	}

	return manager.Store.GetPeersForAPeer(account.Id, peerKey)
}

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key err wit ha code codes.Unauthenticated
// will be returned, meaning the key is invalid
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
func (manager *AccountManager) AddPeer(setupKey string, peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, err := manager.Store.GetAccountBySetupKey(setupKey)
	if err != nil {
		//todo
		return nil, err
	}

	network := account.Network
	nextIp := network.GetNextIP()
	network.LastIP = nextIp

	newPeer := &Peer{
		AccountId: account.Id,
		Key:       peerKey,
		SetupKey:  &SetupKey{Key: setupKey},
		Addr:      nextIp.String(),
	}

	// save changes of the Network
	err = manager.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding peer")
	}

	err = manager.Store.SavePeer(newPeer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding peer")
	}

	return newPeer, nil

}
