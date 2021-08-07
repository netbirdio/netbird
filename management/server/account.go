package server

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
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
	Peers     map[string]*Peer
}

// SetupKey represents a pre-authorized key used to register machines (peers)
// One key might have multiple machines
type SetupKey struct {
	Key string
}

// Peer represents a machine connected to the network.
// The Peer is a Wireguard peer identified by a public key
type Peer struct {
	// Wireguard public key
	Key string
	// A setup key this peer was registered with
	SetupKey *SetupKey
	// IP address of the Peer
	IP net.IP
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

func (manager *AccountManager) GetAccount(accountId string) (*Account, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, err := manager.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed retrieving account")
	}

	return account, nil
}

func (manager *AccountManager) AccountExists(accountId string) (*bool, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	res := false
	_, err := manager.Store.GetAccount(accountId)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return &res, nil
		} else {
			return nil, err
		}
	}

	res = true
	return &res, nil
}

// AddAccount generates a new Account with a provided accountId and saves to the Store
func (manager *AccountManager) AddAccount(accountId string) (*Account, error) {

	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, _ := newAccountWithId(accountId)

	err := manager.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed creating account")
	}

	return account, nil

}

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key err wit ha code codes.Unauthenticated
// will be returned, meaning the key is invalid
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
// If the specified setupKey is empty then a new Account will be created //todo make it more explicit?
func (manager *AccountManager) AddPeer(setupKey string, peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	var account *Account
	var err error
	var sk *SetupKey
	if len(setupKey) == 0 {
		// Empty setup key, create a new account for it.
		account, sk = newAccount()
	} else {
		sk = &SetupKey{Key: setupKey}
		account, err = manager.Store.GetAccountBySetupKey(sk.Key)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "unknown setupKey %s", setupKey)
		}
	}

	var takenIps []net.IP
	for _, peer := range account.Peers {
		takenIps = append(takenIps, peer.IP)
	}

	network := account.Network
	nextIp, _ := AllocatePeerIP(network.Net, takenIps)

	newPeer := &Peer{
		Key:      peerKey,
		SetupKey: sk,
		IP:       nextIp,
	}

	account.Peers[newPeer.Key] = newPeer
	err = manager.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding peer")
	}

	return newPeer, nil

}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(accountId string) (*Account, *SetupKey) {

	log.Debugf("creating new account")

	setupKeyId := uuid.New().String()
	setupKeys := make(map[string]*SetupKey)
	setupKey := &SetupKey{Key: setupKeyId}
	setupKeys[setupKeyId] = setupKey
	network := &Network{
		Id:  uuid.New().String(),
		Net: net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 192, 0, 0}},
		Dns: ""}
	peers := make(map[string]*Peer)

	log.Debugf("created new account %s with setup key %s", accountId, setupKeyId)

	return &Account{Id: accountId, SetupKeys: setupKeys, Network: network, Peers: peers}, setupKey
}

// newAccount creates a new Account with a default SetupKey (doesn't store in a Store)
func newAccount() (*Account, *SetupKey) {
	accountId := uuid.New().String()
	return newAccountWithId(accountId)
}
